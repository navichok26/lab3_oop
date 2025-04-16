#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <dlfcn.h>
#include <errno.h>

#if defined(__x86_64__)
#define ARCH_REGS struct user_regs_struct
#define ARCH_IP rip
#define ARCH_SP rsp
#define ARCH_SYSCALL_RET rax
#define ARCH_ARG1 rdi
#define ARCH_ARG2 rsi
#define ARCH_ARG3 rdx
#define ARCH_ARG4 r10
#define ARCH_ARG5 r8
#define ARCH_ARG6 r9
#elif defined(__i386__)
#define ARCH_REGS struct user_regs_struct
#define ARCH_IP eip
#define ARCH_SP esp
#define ARCH_SYSCALL_RET eax
#define ARCH_ARG1 ebx
#define ARCH_ARG2 ecx
#define ARCH_ARG3 edx
#define ARCH_ARG4 esi
#define ARCH_ARG5 edi
#define ARCH_ARG6 ebp
#else
#error "Архитектура не поддерживается"
#endif

// Функция для записи данных в память процесса
void write_process_memory(pid_t pid, void *dst, const void *src, size_t len) {
    size_t i;
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;

    for (i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, s + i, (i + sizeof(long) > len) ? (len - i) : sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, d + i, word) == -1) {
            perror("ptrace(POKETEXT)");
            exit(EXIT_FAILURE);
        }
    }
}

// Функция для чтения данных из памяти процесса
void read_process_memory(pid_t pid, void *dst, const void *src, size_t len) {
    size_t i;
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;

    for (i = 0; i < len; i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKTEXT, pid, s + i, NULL);
        if (word == -1 && errno) {
            perror("ptrace(PEEKTEXT)");
            exit(EXIT_FAILURE);
        }
        memcpy(d + i, &word, (i + sizeof(long) > len) ? (len - i) : sizeof(long));
    }
}

// Функция для выполнения вызова функции в удаленном процессе
long remote_call(pid_t pid, void *func_addr, long *args, int arg_count, int restore_regs) {
    ARCH_REGS regs, original_regs;
    long ret;

    // Сохраняем текущие регистры
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace(GETREGS)");
        exit(EXIT_FAILURE);
    }

    // Сохраняем оригинальные регистры для восстановления
    if (restore_regs)
        memcpy(&original_regs, &regs, sizeof(ARCH_REGS));

    // Устанавливаем адрес функции
    regs.ARCH_IP = (unsigned long)func_addr;

    // Устанавливаем аргументы функции
    if (arg_count > 0) regs.ARCH_ARG1 = args[0];
    if (arg_count > 1) regs.ARCH_ARG2 = args[1];
    if (arg_count > 2) regs.ARCH_ARG3 = args[2];
    if (arg_count > 3) regs.ARCH_ARG4 = args[3];
    if (arg_count > 4) regs.ARCH_ARG5 = args[4];
    if (arg_count > 5) regs.ARCH_ARG6 = args[5];

    // Выравниваем стек (требуется x86-64 ABI)
    regs.ARCH_SP = (regs.ARCH_SP & ~0xF) - 8;

    // Устанавливаем регистры
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace(SETREGS)");
        exit(EXIT_FAILURE);
    }

    // Сохраняем оригинальный код по адресу функции
    unsigned long original_data = ptrace(PTRACE_PEEKTEXT, pid, regs.ARCH_IP, NULL);
    if (original_data == -1 && errno) {
        perror("ptrace(PEEKTEXT) - чтение оригинального кода");
        exit(EXIT_FAILURE);
    }

    // Вставляем инструкцию int 3 (breakpoint) для остановки после выполнения
    unsigned long int3 = (original_data & ~0xFF) | 0xCC;
    if (ptrace(PTRACE_POKETEXT, pid, regs.ARCH_IP, int3) == -1) {
        perror("ptrace(POKETEXT) - int3");
        exit(EXIT_FAILURE);
    }

    // Продолжаем выполнение до достижения точки останова
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("ptrace(CONT)");
        // Восстанавливаем оригинальный код
        ptrace(PTRACE_POKETEXT, pid, regs.ARCH_IP, original_data);
        exit(EXIT_FAILURE);
    }
    
    int status;
    waitpid(pid, &status, 0);

    // Восстанавливаем оригинальный код
    if (ptrace(PTRACE_POKETEXT, pid, regs.ARCH_IP, original_data) == -1) {
        perror("ptrace(POKETEXT) - восстановление");
        exit(EXIT_FAILURE);
    }

    // Проверяем, что процесс остановился по breakpoint
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "Процесс не остановился по SIGTRAP (сигнал: %d)\n", WSTOPSIG(status));
        exit(EXIT_FAILURE);
    }

    // Получаем регистры для извлечения возвращаемого значения
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace(GETREGS) - after call");
        exit(EXIT_FAILURE);
    }

    // Сохраняем возвращаемое значение
    ret = regs.ARCH_SYSCALL_RET;

    // Восстанавливаем оригинальные регистры, если требуется
    if (restore_regs) {
        if (ptrace(PTRACE_SETREGS, pid, NULL, &original_regs) == -1) {
            perror("ptrace(SETREGS) - restore");
            exit(EXIT_FAILURE);
        }
    }

    return ret;
}

// Добавьте эту функцию для нахождения адресов в адресном пространстве целевого процесса
void *find_remote_symbol(pid_t pid, const char *lib_name, const char *symbol_name) {
    char maps_path[64];
    char line[1024];
    unsigned long lib_addr = 0;
    FILE *maps;

    sprintf(maps_path, "/proc/%d/maps", pid);
    maps = fopen(maps_path, "r");
    if (!maps) {
        perror("Ошибка при открытии карты памяти процесса");
        return NULL;
    }

    // Ищем базовый адрес библиотеки
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, lib_name)) {
            sscanf(line, "%lx-", &lib_addr);
            break;
        }
    }
    fclose(maps);

    if (!lib_addr) {
        fprintf(stderr, "Не удалось найти библиотеку %s в процессе %d\n", lib_name, pid);
        return NULL;
    }

    // Находим смещение символа в нашем процессе
    void *handle = dlopen(lib_name, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Не удалось загрузить библиотеку %s: %s\n", lib_name, dlerror());
        return NULL;
    }

    void *symbol = dlsym(handle, symbol_name);
    if (!symbol) {
        fprintf(stderr, "Символ %s не найден в библиотеке %s: %s\n", symbol_name, lib_name, dlerror());
        dlclose(handle);
        return NULL;
    }

    // Получаем базовый адрес библиотеки в нашем процессе
    Dl_info info;
    if (!dladdr(symbol, &info)) {
        fprintf(stderr, "Не удалось получить информацию о символе %s\n", symbol_name);
        dlclose(handle);
        return NULL;
    }

    // Вычисляем смещение внутри библиотеки
    unsigned long offset = (unsigned long)symbol - (unsigned long)info.dli_fbase;
    dlclose(handle);

    // Возвращаем адрес символа в удаленном процессе
    return (void*)(lib_addr + offset);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Использование: %s <pid> <путь_к_библиотеке.so>\n", argv[0]);
        return EXIT_FAILURE;
    }

    pid_t pid = atoi(argv[1]);
    char *lib_path = argv[2];
    
    // Проверяем существование библиотеки
    if (access(lib_path, F_OK) != 0) {
        fprintf(stderr, "Библиотека %s не найдена\n", lib_path);
        return EXIT_FAILURE;
    }

    // Получаем полный путь к библиотеке
    char abs_lib_path[4096];
    if (realpath(lib_path, abs_lib_path) == NULL) {
        perror("realpath");
        return EXIT_FAILURE;
    }

    printf("Инъекция библиотеки %s в процесс %d\n", abs_lib_path, pid);

    // Присоединяемся к процессу
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace(ATTACH)");
        return EXIT_FAILURE;
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Не удалось остановить процесс\n");
        return EXIT_FAILURE;
    }

    printf("Процесс остановлен, начинаем инъекцию\n");

    // Получаем адреса функций в целевом процессе
    void *dlopen_addr = find_remote_symbol(pid, "libdl.so.2", "dlopen");
    if (!dlopen_addr) {
        dlopen_addr = find_remote_symbol(pid, "libc.so.6", "dlopen");
    }

    if (!dlopen_addr) {
        fprintf(stderr, "Не удалось найти dlopen в целевом процессе\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    printf("Адрес dlopen: %p\n", dlopen_addr);

    // Находим malloc в целевом процессе
    void *malloc_addr = find_remote_symbol(pid, "libc.so.6", "malloc");
    if (!malloc_addr) {
        fprintf(stderr, "Не удалось найти malloc в целевом процессе\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    // Вызываем malloc в удаленном процессе
    long malloc_args[1];
    malloc_args[0] = strlen(abs_lib_path) + 1;
    long remote_path_addr = remote_call(pid, malloc_addr, malloc_args, 1, 1);

    if (remote_path_addr == 0) {
        fprintf(stderr, "Удаленный malloc вернул NULL\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    printf("Выделена удаленная память по адресу: 0x%lx\n", remote_path_addr);

    // Записываем путь к библиотеке в удаленную память
    write_process_memory(pid, (void *)remote_path_addr, abs_lib_path, strlen(abs_lib_path) + 1);

    // Вызываем dlopen в удаленном процессе
    long dlopen_args[2];
    dlopen_args[0] = remote_path_addr;  // путь к библиотеке
    dlopen_args[1] = RTLD_NOW | RTLD_GLOBAL;  // флаги
    long handle = remote_call(pid, dlopen_addr, dlopen_args, 2, 1);

    if (handle == 0) {
        fprintf(stderr, "dlopen в удаленном процессе вернул NULL\n");
        
        // Получаем сообщение об ошибке от dlerror
        void *remote_dlerror_addr = find_remote_symbol(pid, "libc.so.6", "dlerror");
        if (remote_dlerror_addr != NULL) {
            long error_msg_addr = remote_call(pid, remote_dlerror_addr, NULL, 0, 1);
            if (error_msg_addr != 0) {
                char error_msg[256] = {0};
                read_process_memory(pid, error_msg, (void *)error_msg_addr, sizeof(error_msg) - 1);
                fprintf(stderr, "dlerror: %s\n", error_msg);
            }
        }
        
        // Освобождаем выделенную память
        void *free_addr = find_remote_symbol(pid, "libc.so.6", "free");
        if (free_addr) {
            long free_args[1] = {remote_path_addr};
            remote_call(pid, free_addr, free_args, 1, 1);
        }
        
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    printf("Библиотека успешно загружена, handle: 0x%lx\n", handle);

    // Освобождаем выделенную память
    void *free_addr = find_remote_symbol(pid, "libc.so.6", "free");
    if (free_addr) {
        long free_args[1] = {remote_path_addr};
        remote_call(pid, free_addr, free_args, 1, 1);
    }

    // Отсоединяемся от процесса
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace(DETACH)");
        return EXIT_FAILURE;
    }

    printf("Инъекция выполнена успешно\n");
    return EXIT_SUCCESS;
}