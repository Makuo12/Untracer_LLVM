#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <map>
#include <dirent.h>
// #include <capstone/capstone.h>
#include <sys/stat.h> 

#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <iterator>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include "data.h"
#include "config.h"

using namespace std;
typedef unsigned char u8;
typedef unsigned long long u64;
int total_paths_found = 0;
int total_coverage_found = 0;

static u8 * trace_blocks;

std::vector<int> guards_hit;

void files(Entry **entries, const char *in_dir, size_t *entry_count)
{

    // 3. Scan directory
    struct dirent **items;
    int count = scandir(in_dir, &items, NULL, alphasort);
    if (count < 0)
    {
        cout << "Failed to scan input directory" << endl;
        exit(1);
    }
    if (count == 0)
    {
        free(items); // Don't forget to free the top-level pointer if count is 0
        cout << "No input files found to fuzz" << endl;
        exit(1);
    }

    // 4. Set up dynamic array variables to replicate std::vector behavior
    int capacity = 10; // Start with an initial capacity
    *entry_count = 0;
    *entries = (Entry *)malloc(capacity * sizeof(Entry));
    if (*entries == NULL)
    {
        cout << "Memory allocation failed for entries array" << endl;
        exit(1);
    }

    struct stat st;
    // 5. Loop through directory items
    for (int i = 0; i < count; ++i)
    {
        if (items[i]->d_type != DT_REG)
        {
            free(items[i]);
            continue;
        }

        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s/%s", in_dir, items[i]->d_name);

        if (stat(file_path, &st) == 0)
        {
            // Resize dynamic array if capacity is reached (std::vector emulation)
            if (*entry_count >= (size_t)capacity)
            {
                capacity *= 2;
                Entry *temp = (Entry *)realloc(*entries, capacity * sizeof(Entry));
                if (temp == NULL)
                {
                    cout << "Memory reallocation failed while scanning entries" << endl;
                    exit(1);
                }
                *entries = temp;
            }
            // Populate the entry data directly into the array block
            Entry *current_entry = &((*entries)[*entry_count]);
            snprintf(current_entry->d_name, sizeof(current_entry->d_name), "%s", items[i]->d_name);
            snprintf(current_entry->file_path, sizeof(current_entry->file_path), "%s", file_path);
            current_entry->st_size = st.st_size;

            (*entry_count)++;
        }
        free(items[i]);
    }
    free(items);

    if (*entry_count == 0)
    {
        free(*entries);
        *entries = NULL;
        cout << "No valid input files found to fuzz" << endl;
        exit(1);
    }
}

void write_testcase(u8 *mem, Entry *entry, const char *input_file)
{
    ofstream file(input_file, std::ios::binary);
    if (!file.is_open())
    {
        cout << "failed to open input file" << endl;
        exit(1);
    }
    file.write((char *)mem, entry->st_size);
    file.close();
}

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
    // csh handle;
    // cs_insn *insn;
    // size_t count;

    // if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    // {
    //     fprintf(stderr, "  [!] Failed to initialize Capstone disassembler\n");
    //     return false;
    // }

    // // Disassemble the buffer we read
    // count = cs_disasm(handle, code_buffer, bytes_read, pc, 1, &insn);

    // bool safe_to_write = false;
    // if (count > 0)
    // {
    //     // If the disassembler managed to decode at least 1 valid instruction,
    //     // verify that it actually matches the exact address we wanted to patch.
    //     if (insn[0].address == pc)
    //     {
    //         safe_to_write = true;
    //     }
    //     cs_free(insn, count);
    // }
    // cs_close(&handle);

    // // 4. Perform the write safely if verified
    // if (!safe_to_write)
    // {
    //     // This prevents the "ghost traps" caused by mid-instruction corruption!
    //     printf("  [-] Skipping unsafe misalignment at PC: 0x%lx\n", pc);
    //     return false;
    // }

    // Move write pointer back to the validated offset location
    f.seekp(offset, std::ios::beg);
    uint8_t TRAP = 0xCC;
    f.write(reinterpret_cast<const char *>(&TRAP), 1);
    f.flush();

    return f.good();
}

void copy_binary(const char *src_path, const char *dst_path)
{
    struct stat st = {0};
    if (stat(src_path, &st) < 0)
    {
        perror(src_path);
        exit(1);
    }
    char *data = (char *)malloc(st.st_size);
    if (data == NULL)
    {
        perror("malloc");
        exit(1);
    }
    FILE *src_file = fopen(src_path, "rb");
    if (src_file == NULL)
    {
        perror(src_path);
        free(data);
        exit(1);
    }
    FILE *dst_file = fopen(dst_path, "wb");
    if (dst_file == NULL)
    {
        perror(dst_path);
        fclose(src_file);
        free(data);
        exit(1);
    }
    if (fread(data, 1, st.st_size, src_file) != (size_t)st.st_size)
    {
        perror(src_path);
        fclose(src_file);
        fclose(dst_file);
        free(data);
        exit(1);
    }
    if (fwrite(data, 1, st.st_size, dst_file) != (size_t)st.st_size)
    {
        perror(dst_path);
        fclose(src_file);
        fclose(dst_file);
        free(data);
        exit(1);
    }
    fclose(src_file);
    fclose(dst_file);
    free(data);
    if (chmod(dst_path, 0777) < 0)
    {
        perror(dst_path);
        exit(1);
    }
}

void init_trace_bits(void)
{
    int shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0666);
    if (shm_id < 0)
    {
        cout << "key failed to get shm id" << endl;
        exit(1);
    }
    // __trace_shm_id = shm_id;
    // if (atexit(__tracer_cleanup_trace_bits) != 0)
    // {
    //     shmctl(shm_id, IPC_RMID, NULL);
    //     FATAL("Failed to register shared memory cleanup");
    // }
    string shm_str = std::to_string(shm_id);
    setenv(SHM_ID_ENV, shm_str.c_str(), 1);
    trace_blocks = (u8 *)shmat(shm_id, 0, 0);
    if (trace_blocks == (u8 *)-1)
    {
        shmctl(shm_id, IPC_RMID, NULL);
        cout << "failed to link trace_bits to memory" << endl;
        exit(1);
    }
}

static void modify(const char *bin_path, map<int, uintptr_t> &bblist) {
    // bool found = false;
    int patched = 0;
    for (auto begin = bblist.begin(); begin != bblist.end(); ++begin) {
        // found = false;
        if (trace_blocks[begin->first] == 0)
        {
            if (write_trap(bin_path, begin->second))
            {
                ++patched;
            }
        }
        // for (auto i : guards_hit)
        // {
        //     if (i == begin->first)
        //     {
        //         found = true;
        //     }
        // }
        // if (found)
        // {
        //     continue;
        // }
        // if (write_trap(bin_path, begin->second))
        // {
        //     ++patched;
        // }
    }
    cout << "Trap was insert by: " << patched << endl;
}

// void read_coverage_file(const char * output)
// {
//     char buf[1024];
//     size_t size = snprintf(NULL, 0, "%s/coverage.txt", output);
//     if (size == 0) {
//         cout << "output not found" << endl;
//     }
//     snprintf(buf, size + 1, "%s/coverage.txt", output);
//     std::ifstream infile(buf);
//     if (!infile.is_open())
//     {
//         std::cerr << "Warning: Could not open coverage file: " << buf << "\n";
//         return;
//     }

//     std::string line;
//     while (std::getline(infile, line))
//     {
//         // Expecting lines formatted as: "guard found <idx>"
//         int idx = std::stoi(line);
//         guards_hit.push_back(idx);
//     }
// }

void clear_coverage(const char * coverage) {
    int fd = open(coverage, O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
        cout << "coverage file could not open" << endl;
        exit(1);
    }
    close(fd);
}

void trace_coverage(
    map<int, uintptr_t> &bblist,
    const char * trace,
    const char * input,
    const char * output
)
{
    char buf[1024];
    size_t size = snprintf(NULL, 0, "%s/coverage.txt", output);
    if (size == 0) {
        cout << "output not found" << endl;
    }
    snprintf(buf, size + 1, "%s/coverage.txt", output);
    char * argv[3];
    argv[0] = const_cast<char *>(trace);
    argv[1] = const_cast<char *>(input);
    argv[2] = nullptr;
    pid_t pid = fork();
    if (pid == 0)
    {
        setenv(COVERAGE, buf, 1);
        execvp(argv[0], argv);
        perror("execvp failed");
        exit(1);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        // read_coverage_file(output);
    }
    else
    {
        perror("fork failed");
        exit(1);
    }
}

bool fork_child(
    map<int, uintptr_t> &bblist,
    const char * trace,
    const char * oracle,
    const char * input,
    const char * output
) {
    char *argv[3];
    argv[0] = const_cast<char *>(oracle);
    argv[1] = const_cast<char *>(input);
    argv[2] = nullptr;
    pid_t pid = fork();
    if (pid == 0)
    {
        // Child
        // ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[0], argv);
    }
    int status;
    waitpid(pid, &status, 0);
    // if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    // {
    //     ptrace(PTRACE_CONT, pid, NULL, NULL); // let it keep running
    //     waitpid(pid, &status, 0);  
    // }
    // if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    // {
    //     struct user_regs_struct regs;
    //     ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    //     u64 back = (regs.rip - 1);
    //     u64 addr = back - 0x400000;
    //     cout << "trap addre " << std::hex << addr << endl;
    //     // Kill the child process
    //     kill(pid, SIGKILL);
    //     waitpid(pid, &status, 0); // reap the zombie
    //     cout << "on trap" << endl;
    //     trace_coverage(bblist, trace, input, output);
    //     return true;           // wait for next stop
    // }
    if (WIFSIGNALED(status))
    {
        int term_sig = WTERMSIG(status);
        if (term_sig == SIGTRAP)
        {
            cout << "on trap signal" << endl;
            trace_coverage(bblist, trace, input, output);
            return true;           // wait for next stop
        }
    }
    return false;
}



void setup_bblist(map<int, uintptr_t> &list, const string &path_to_bblock)
{
    FILE *csv = fopen(path_to_bblock.c_str(), "r");
    if (!csv)
    {
        perror("open csv");
        exit(1);
    }
    char line[256];
    fgets(line, sizeof(line), csv);
    // std::size_t patched = 0;
    std::size_t index;
    uintptr_t pc;
    uintptr_t flags;
    while (fgets(line, sizeof(line), csv))
    {
        if (sscanf(line, "%zu,0x%lx,%lu", &index, &pc, &flags) != 3)
            continue;
        
        list[index] = pc;
    }
    fclose(csv);
}

u8 * read_file(Entry *entry) {
    int fd = open(entry->file_path, O_RDONLY);
    if (fd < 0)
    {
        entry->has_issues = 1;
        char err_msg[512];
        snprintf(err_msg, sizeof(err_msg), "Failed to open file: %s", entry->d_name);
        return nullptr;
    }
    u8 *mem = (u8 *)mmap(NULL, entry->st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mem == MAP_FAILED)
    {
        entry->has_issues = 1;
        char err_msg[512];
        snprintf(err_msg, sizeof(err_msg), "Failed to map file: %s", entry->d_name);
        return nullptr;
    }
    return mem;
}


int main(int argc, char *argv[])
{
    const char *oracle = nullptr;
    const char *trace = nullptr;
    const char *blist = nullptr;
    const char *output = nullptr;
    const char *input = nullptr;
    const char *in_dir = nullptr;
    map<int, uintptr_t> bblist;
    Entry * entries;
    size_t entry_count = 0;
    int opt;
    while ((opt = getopt(argc, argv, "o:t:b:p:i:d:")) != -1)
    {
        switch (opt)
        {
        case 'o':
            oracle = optarg;
            break;
        case 't':
            trace = optarg;
            break;
        case 'b':
            blist = optarg;
            break;
        case 'p':
            output = optarg;
            break;
        case 'i':
            input = optarg;
            break;
        case 'd':
            in_dir = optarg;
            break;
        default:
// ./untracer -o ./output/main.oracle -t ./output/pdftotext -b ./output/text -p output -i ./output/cur_input.pdf -d pdf_test
            fprintf(stderr, "usage: %s -o <oracle> -t <trace> -b <blist> -p <output> -i <input> -d <input dir>\n", argv[0]);
            return 1;
        }
    }
    if (!oracle || !trace || !blist || !output || !input || !in_dir)
    {
        fprintf(stderr, "[ERROR] Missing required arguments.\n");
        fprintf(stderr, "usage: %s -o <oracle> -t <trace> -b <blist> -p <output> -i <input> -d <input dir>\n", argv[0]);
        return 1;
    }
    // After tracing finishes, open the coverage file and load indices into a vector
    init_trace_bits();
    memset(trace_blocks, 0, MAP_SIZE);
    files(&entries, in_dir, &entry_count);
    setup_bblist(bblist, blist);
    copy_binary(trace, oracle);
    modify(oracle, bblist);
    std::cout << "Successfully loaded " << bblist.size() << " guard indices into the vector.\n";
    bool result = false;
    size_t current = 0;
    while (true) {

        if (current >= entry_count) {
            cout << "full pass done" << endl;
            exit(1);
        }
        if (result) {
            copy_binary(trace, oracle);
            modify(oracle, bblist);
            result = false;
        }
        Entry * entry = &entries[current++];
        if (entry->has_issues) {
            continue;
        }
        u8 * mem = read_file(entry);
        if (mem == nullptr) {
            continue;
        }
        write_testcase(mem, entry, input);
        munmap(mem, entry->st_size);
        result = fork_child(bblist, trace, oracle, input, output);
    }
    return 0;
}