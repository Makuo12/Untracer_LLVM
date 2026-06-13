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
#include <sys/stat.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <ctime>
#include <cstring>
#include <iterator>
#include <cstdio>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include "data.h"
#include "config.h"
#include "types.h"

using namespace std;
int total_paths_found = 0;
int total_coverage_found = 0;

static u8 *trace_blocks;

std::vector<int> guards_hit;

static u8 virgin_blocks[MAP_SIZE];

Entry *all_entries = NULL;
size_t entry_total_count = 0;
size_t number_execs = 0;

int capacity = 100;

char *crash_dir = NULL;
char *trace_dir = NULL;

enum class Result
{
    TRAP, // TRAP means new path
    CRASH,
    NORMAL
};

void add_file(const char *filename, const char *file_path, size_t size)
{
    if (filename == nullptr || file_path == nullptr)
    {
        cerr << "Error: null filename or file_path passed to add_file" << endl;
        return;
    }

    if (entry_total_count >= (size_t)capacity)
    {
        size_t new_capacity = (capacity == 0) ? 1 : capacity * 2;
        Entry *temp = (Entry *)realloc(all_entries, new_capacity * sizeof(Entry));
        if (temp == nullptr)
        {
            cerr << "Memory reallocation failed while scanning entries" << endl;
            exit(1);
        }
        all_entries = temp;
        capacity = new_capacity;
    }

    Entry *current_entry = &all_entries[entry_total_count];
    snprintf(current_entry->d_name, sizeof(current_entry->d_name), "%s", filename);
    snprintf(current_entry->file_path, sizeof(current_entry->file_path), "%s", file_path);
    current_entry->st_size = size;

    entry_total_count++;
}

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

void suppress_output()
{
    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null == -1)
    {
        perror("Failed to open /dev/null");
        return;
    }

    dup2(dev_null, STDOUT_FILENO); // redirect stdout (fd 1)
    dup2(dev_null, STDERR_FILENO); // redirect stderr (fd 2)

    close(dev_null); // original fd no longer needed
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

void init_trace_blocks(void)
{
    int shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0666);
    if (shm_id < 0)
    {
        cout << "key failed to get shm id" << endl;
        exit(1);
    }
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


bool has_new_block(void)
{
    bool found = false;
    for (int i = 0; i < MAP_SIZE; ++i)
    {
        if (trace_blocks[i] && virgin_blocks[i] == 0)
        {
            found = true;
            virgin_blocks[i] = 1;
        }
    }
    return found;
}

std::string generateTimestampFilename(const std::string &extension = ".pdf")
{
    std::time_t now = std::time(nullptr);
    std::tm *localTime = std::localtime(&now);

    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", localTime);

    return std::string(buffer) + extension;
}

void write_to_file(const char *input, size_t file_size, Result result)
{
    string timestamp = generateTimestampFilename();
    char buf[1024];
    switch (result)
    {
    case Result::CRASH:
    {
        size_t size = snprintf(NULL, 0, "%s/%s", crash_dir, timestamp.c_str());
        snprintf(buf, size + 1, "%s/%s", crash_dir, timestamp.c_str());
        copy_binary(input, buf);
    }
    default:
    {
        size_t size = snprintf(NULL, 0, "%s/%s", trace_dir, timestamp.c_str());
        snprintf(buf, size + 1, "%s/%s", trace_dir, timestamp.c_str());
        copy_binary(input, buf);
        add_file(timestamp.c_str(), buf, file_size);
    }
    }
}

Result trace_coverage(
    const char *trace,
    const char *input,
    const bool first_pass,
    const size_t file_size)
{
    char *argv[3];
    memset(trace_blocks, 0, MAP_SIZE);
    argv[0] = const_cast<char *>(trace);
    argv[1] = const_cast<char *>(input);
    argv[2] = nullptr;
    ++number_execs;
    pid_t pid = fork();
    if (pid == 0)
    {
        // We dont set the environment because we want to calculate coverage in trace blocks
        suppress_output();
        execvp(argv[0], argv);
        perror("execvp failed");
        exit(1);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status))
        {
            write_to_file(input, file_size, Result::CRASH);
            return Result::CRASH;
        }
        else
        {
            bool result = has_new_block();
            if (result && !first_pass)
            {
                // We only want to write out input if we are not in first pass and new block found
                write_to_file(input, file_size, Result::TRAP);
                return Result::TRAP;
            }
            return Result::NORMAL;
        }
    }
    else
    {
        perror("fork failed");
        exit(1);
    }
}



u8 *read_file(Entry *entry)
{
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

void first_pass(Entry *entries, size_t *entry_count, const char *trace, const char *input)
{
    Result result = Result::NORMAL;
    for (size_t i = 0; i < *entry_count; ++i)
    {
        Entry *entry = &entries[i];
        if (entry->has_issues)
        {
            continue;
        }
        u8 *mem = read_file(entry);
        if (mem == nullptr)
        {
            continue;
        }
        write_testcase(mem, entry, input);
        munmap(mem, entry->st_size);
        result = trace_coverage(trace, input, true, entry->st_size);
        if (result == Result::CRASH)
        {
            entry->has_issues = true;
            result = Result::NORMAL;
        }
    }
}

void mutate(u8 *mem, int position)
{
    mem[position >> 3] ^= (128 >> (position & 7));
}

void setup_dir(const char *output)
{
    size_t crash_name_size = snprintf(NULL, 0, "%s/%s", output, "crash");
    size_t trace_name_size = snprintf(NULL, 0, "%s/%s", output, "trace");
    crash_dir = (char *)malloc(crash_name_size + 1);
    trace_dir = (char *)malloc(trace_name_size + 1);
    if (crash_dir == NULL || trace_dir == NULL)
    {
        cout << "could not setup crash and trace dir" << endl;
        exit(1);
    }
    snprintf(crash_dir, crash_name_size + 1, "%s/%s", output, "crash");
    snprintf(trace_dir, trace_name_size + 1, "%s/%s", output, "trace");
    mkdir(crash_dir, 0777);
    mkdir(trace_dir, 0777);
}

int main(int argc, char *argv[])
{
    const char *trace = nullptr;
    const char *output = nullptr;
    const char *input = nullptr;
    const char *in_dir = nullptr;
    int opt;
    while ((opt = getopt(argc, argv, "t:p:i:d:")) != -1)
    {
        switch (opt)
        {
        case 't':
            trace = optarg;
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
            fprintf(stderr, "usage: %s-t <trace> -p <output> -i <input> -d <input dir>\n", argv[0]);
            return 1;
        }
    }
    if (!trace || !output || !input || !in_dir)
    {
        fprintf(stderr, "[ERROR] Missing required arguments.\n");
        fprintf(stderr, "usage: %s-t <trace> -p <output> -i <input> -d <input dir>\n", argv[0]);
        return 1;
    }
    // After tracing finishes, open the coverage file and load indices into a vector
    init_trace_blocks();
    memset(trace_blocks, 0, MAP_SIZE);
    memset(virgin_blocks, 0, MAP_SIZE);
    files(&all_entries, in_dir, &entry_total_count);
    setup_dir(output);
    string stat_filename = output + string("/stats");
    {
        ofstream filestream(stat_filename);
        std::string header = "elapsed,current,execs\n";
        filestream.write(header.c_str(), header.size());
        filestream.close();
    }
    std::cout << "Running full pass of all inputs" << endl;
    first_pass(all_entries, &entry_total_count, trace, input);
    std::cout << "Done with full pass of all inputs" << endl;
    std::cout << "Running fuzzer with mutations" << endl;
    cout << "Setting up timer" << endl;
    auto start_time = std::chrono::system_clock::now();
    std::time_t now_t = std::chrono::system_clock::to_time_t(start_time);
    std::cout << "Start time: " << std::ctime(&now_t);
    Result result = Result::NORMAL;
    time_t time_count = 1 * TIME_SET;
    size_t current = 0;
    while (true)
    {
        if (current >= entry_total_count)
        {
            current = 0;
            auto count = 0;
            for (int i = 0; i < MAP_SIZE; ++i)
            {
                if (trace_blocks[i] == 1)
                {
                    count++;
                }
            }
            cout << "full pass done" << " trace count: " << count << endl;
        }
        Entry *entry = &all_entries[current++];
        if (entry->has_issues)
        {
            continue;
        }
        u8 *mem = read_file(entry);
        if (mem == nullptr)
        {
            continue;
        }
        size_t len = entry->st_size << 3;
        for (size_t i = 0; i < len; ++i)
        {
            mutate(mem, i);
            write_testcase(mem, entry, input);
            mutate(mem, i);
            result = trace_coverage(trace, input, false, entry->st_size);
            if (result == Result::CRASH)
            {
                entry->has_issues = true;
                result = Result::NORMAL;
                break;
            }
            // check time
            {
                auto now = chrono::system_clock::now();
                auto time_now = chrono::system_clock::to_time_t(now);
                auto time_past = chrono::duration_cast<std::chrono::hours>(now - start_time);
                if (time_past.count() > time_count)
                {
                    {
                        ofstream filestream(stat_filename, std::ios::app);
                        std::string data;
                        data += std::to_string(time_past.count());
                        data += "hrs,";
                        data += std::to_string(time_now);
                        data += ",";
                        data += std::to_string(number_execs);
                        data += "\n";
                        filestream.write(data.c_str(), data.size());
                        filestream.close();
                        time_count *= TIME_SET;
                    }
                }
            }
        }
        munmap(mem, entry->st_size);
    }
    return 0;
}