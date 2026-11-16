/* A fresh executable keeps stdout untouched until the operation under test. */
typedef struct guest_file FILE;
typedef unsigned long size_t;

extern FILE* stdout;
extern FILE* stderr;
int atoi(const char* text);
int dup2(int source, int destination);
int setvbuf(FILE* stream, char* buffer, int mode, size_t size);
FILE* freopen(const char* path, const char* mode, FILE* stream);
int snprintf(char* buffer, size_t size, const char* format, ...);
int printf(const char* format, ...);
int fprintf(FILE* stream, const char* format, ...);
int fputc(int character, FILE* stream);
size_t fwrite(const void* data, size_t size, size_t count, FILE* stream);
size_t strlen(const char* text);

static int emit(const char* text, char writer) {
    size_t length = strlen(text);

    if (writer == 'p') {
        return printf("%s", text) == (int)length;
    }
    if (writer == 'w') {
        return fwrite(text, 1, length, stdout) == length;
    }
    for (; *text; ++text) {
        if (fputc(*text, stdout) < 0) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        return 10;
    }

    int target = atoi(argv[1]);
    int afterWrite = argv[2][0] == 'a';
    char mode = argv[3][0];
    char writer = argv[4][0];

    if (mode != 'd' && setvbuf(stdout, 0, mode == 'u' ? 2 : mode == 'l' ? 1 : 0, 0)) {
        return 11;
    }
    if (afterWrite && !emit("o", writer)) {
        return 12;
    }
    if (target >= 0) {
        if (argv[2][0] == 'r') {
            char path[64];

            snprintf(path, sizeof(path), "/proc/self/fd/%d", target);
            if (!freopen(path, "w", stdout)) {
                return 13;
            }
        } else if (dup2(target, 1) != 1) {
            return 13;
        }
    }
    if (!emit(afterWrite ? "ut\n" : "out\n", writer) || fprintf(stderr, "err\n") != 4) {
        return 14;
    }
    return 0;
}
