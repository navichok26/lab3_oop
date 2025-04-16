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

    // Вставляем инструкцию int 3 (breakpoint) для остановки после выполнения
    unsigned long data = ptrace(PTRACE_PEEKTEXT, pid, regs.ARCH_IP, NULL);
    unsigned long int3 = (data & ~0xFF) | 0xCC;
    if (ptrace(PTRACE_POKETEXT, pid, regs.ARCH_IP, int3) == -1) {
        perror("ptrace(POKETEXT) - int3");
        exit(EXIT_FAILURE);
    }

    // Продолжаем выполнение до достижения точки останова
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("ptrace(CONT)");
        exit(EXIT_FAILURE);
    }
    
    int status;
    waitpid(pid, &status, 0);

    // Проверяем, что процесс остановился по breakpoint
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "Процесс не остановился по SIGTRAP\n");
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

    // Получаем адрес функции dlopen в целевом процессе
    void *dlopen_addr = (void *)dlsym(RTLD_NEXT, "dlopen");
    if (dlopen_addr == NULL) {
        fprintf(stderr, "Не удалось найти dlopen: %s\n", dlerror());
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    printf("Адрес dlopen: %p\n", dlopen_addr);

    // Выделяем память в удаленном процессе для пути к библиотеке
    void *remote_dlopen_addr = dlopen_addr;
    void *remote_malloc_addr = (void *)dlsym(RTLD_NEXT, "malloc");
    
    if (remote_malloc_addr == NULL) {
        fprintf(stderr, "Не удалось найти malloc: %s\n", dlerror());
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    // Вызываем malloc в удаленном процессе
    long malloc_args[1];
    malloc_args[0] = strlen(abs_lib_path) + 1;
    long remote_path_addr = remote_call(pid, remote_malloc_addr, malloc_args, 1, 1);

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
    long handle = remote_call(pid, remote_dlopen_addr, dlopen_args, 2, 1);

    if (handle == 0) {
        fprintf(stderr, "dlopen в удаленном процессе вернул NULL\n");
        
        // Получаем сообщение об ошибке от dlerror
        void *remote_dlerror_addr = (void *)dlsym(RTLD_NEXT, "dlerror");
        if (remote_dlerror_addr != NULL) {
            long error_msg_addr = remote_call(pid, remote_dlerror_addr, NULL, 0, 1);
            if (error_msg_addr != 0) {
                char error_msg[256] = {0};
                read_process_memory(pid, error_msg, (void *)error_msg_addr, sizeof(error_msg) - 1);
                fprintf(stderr, "dlerror: %s\n", error_msg);
            }
        }
        
        // Освобождаем выделенную память
        void *remote_free_addr = (void *)dlsym(RTLD_NEXT, "free");
        if (remote_free_addr != NULL) {
            long free_args[1] = {remote_path_addr};
            remote_call(pid, remote_free_addr, free_args, 1, 1);
        }
        
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return EXIT_FAILURE;
    }

    printf("Библиотека успешно загружена, handle: 0x%lx\n", handle);

    // Освобождаем выделенную память
    void *remote_free_addr = (void *)dlsym(RTLD_NEXT, "free");
    long free_args[1] = {remote_path_addr};
    remote_call(pid, remote_free_addr, free_args, 1, 1);

    // Отсоединяемся от процесса
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace(DETACH)");
        return EXIT_FAILURE;
    }

    printf("Инъекция выполнена успешно\n");
    return EXIT_SUCCESS;
}