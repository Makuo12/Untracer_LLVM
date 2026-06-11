#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <capstone/capstone.h>
#include <unistd.h>

#include <fstream>

// x86 INT3 trap byte

std::vector<int> guards_hit;

static bool write_trap(const char *bin_path, uintptr_t pc)
{
    uintptr_t offset = pc - 0x400000;
    // 1. Open file in read/write binary mode
    std::fstream f(bin_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!f.is_open())
    {
        fprintf(stderr, "  [!] failed to open %s\n", bin_path);
        return false;
    }
    // 2. Read the next 15 bytes from this PC address to inspect them
    uint8_t code_buffer[15];
    f.seekg(offset, std::ios::beg);
    f.read(reinterpret_cast<char *>(code_buffer), sizeof(code_buffer));
    std::streamsize bytes_read = f.gcount();

    if (bytes_read == 0)
    {
        return false;
    }
    // 3. Initialize Capstone Engine for x86_64
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "  [!] Failed to initialize Capstone disassembler\n");
        return false;
    }

    // Disassemble the buffer we read
    count = cs_disasm(handle, code_buffer, bytes_read, pc, 1, &insn);

    bool safe_to_write = false;
    if (count > 0)
    {
        // If the disassembler managed to decode at least 1 valid instruction,
        // verify that it actually matches the exact address we wanted to patch.
        if (insn[0].address == pc)
        {
            safe_to_write = true;
        }
        cs_free(insn, count);
    }
    cs_close(&handle);

    // 4. Perform the write safely if verified
    if (!safe_to_write)
    {
        // This prevents the "ghost traps" caused by mid-instruction corruption!
        printf("  [-] Skipping unsafe misalignment at PC: 0x%lx\n", pc);
        return false;
    }

    // Move write pointer back to the validated offset location
    f.seekp(offset, std::ios::beg);
    uint8_t TRAP = 0xCC;
    f.write(reinterpret_cast<const char *>(&TRAP), 1);
    f.flush();

    return f.good();
}

// Run the targeted oracle binary under ptrace supervision
void run_and_trace_oracle(std::string &oracle_path)
{
    pid_t child = fork();

    if (child == 0)
    {
        // --- CHILD PROCESS ---
        // Allow the parent to trace this process
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
        {
            perror("ptrace traceme failed");
            exit(1);
        }
        char *args[] = {(char *)"./output/main.oracle", (char *)"./README.pdf", NULL};
        // Execute the oracle target binary
        // (Assuming no arguments for now, add them if required)
        execvp(oracle_path.data(), args);

        // If execl returns, an error occurred
        perror("execl failed");
        exit(1);
    }
    else if (child > 0)
    {
        // --- PARENT PROCESS (TRACER) ---
        int status;
        struct user_regs_struct regs;

        std::cout << "[Tracer] Monitoring child PID: " << child << "\n";

        while (true)
        {
            // Wait for the child process to change state (e.g., hit a signal)
            waitpid(child, &status, 0);

            if (WIFEXITED(status))
            {
                std::cout << "[Tracer] Child exited normally with status " << WEXITSTATUS(status) << "\n";
                break;
            }
            if (WIFSIGNALED(status))
            {
                std::cout << "[Tracer] Child terminated by signal " << WTERMSIG(status) << "\n";
                break;
            }

            // Check if the child stopped due to a SIGTRAP (our injected trap)
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
            {
                // Read the child's CPU registers
                if (ptrace(PTRACE_GETREGS, child, nullptr, &regs) < 0)
                {
                    perror("ptrace getregs failed");
                    break;
                }

                // On x86_64, hitting an INT3 trap increments the Instruction Pointer ($RIP$) by 1 byte.
                // To get the actual address where your trap was written, subtract 1.
                uintptr_t trap_address = regs.rip - 1;

                std::cout << "\n[!!!] TRAP HIT at Memory Address: 0x" << std::hex << trap_address << std::dec << "\n";

                /* OPTIONAL STEP: If you want the target binary to keep running past the trap:
                 1. You would have to restore the original byte over the 0xCC trap instruction.
                 2. Rewind $RIP$ back to the original address:
                    regs.rip = trap_address;
                    ptrace(PTRACE_SETREGS, child, nullptr, &regs);
                */

                // Resume the child process execution
                ptrace(PTRACE_CONT, child, nullptr, nullptr);
            }
            else
            {
                // If the child stopped for some other reason/signal, just let it continue
                ptrace(PTRACE_CONT, child, nullptr, nullptr);
            }
        }
    }
    else
    {
        perror("fork failed");
    }
}

static std::size_t patch_from_csv(const char *bin_path, const char *csv_path)
{
    FILE *csv = fopen(csv_path, "r");
    if (!csv)
    {
        perror("open csv");
        return 0;
    }

    char line[256];
    fgets(line, sizeof(line), csv);

    std::size_t patched = 0;
    std::size_t index;
    uintptr_t pc;
    uintptr_t flags;

    while (fgets(line, sizeof(line), csv))
    {
        if (sscanf(line, "%zu,0x%lx,%lu", &index, &pc, &flags) != 3)
            continue;
        bool found = false;
        for (auto i : guards_hit) {
            if (i == (int)index) {
                found = true;
            }
        }
        if (found) {
            continue;
        }
        if (write_trap(bin_path, pc))
        {
            ++patched;
        }
    }

    fclose(csv);
    return patched;
}

void read_coverage_file(const std::string &filename)
{
    std::ifstream infile(filename);
    if (!infile.is_open())
    {
        std::cerr << "Warning: Could not open coverage file: " << filename << "\n";
        return;
    }

    std::string line;
    while (std::getline(infile, line))
    {
        // Expecting lines formatted as: "guard found <idx>"
        int idx = std::stoi(line);
        guards_hit.push_back(idx);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <binary> <pcs.csv>\n", argv[0]);
        return 1;
    }
    // After tracing finishes, open the coverage file and load indices into a vector
    std::string coverage_filename = "./output/coverage_log.txt";
    read_coverage_file(coverage_filename);
    std::cout << "Successfully loaded " << guards_hit.size() << " guard indices into the vector.\n";
    std::size_t patched = patch_from_csv(argv[1], argv[2]);
    printf("[done] %zu trap(s) written\n", patched);

    std::string target_oracle = "./output/main.oracle";
    std::cout << "Starting tracing execution loop...\n";

    // This executes your target oracle binary, which hits the sanitizers
    // and writes to "coverage_log.txt"
    run_and_trace_oracle(target_oracle);
    return 0;
}