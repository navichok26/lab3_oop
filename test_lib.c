#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <time.h>

extern volatile sig_atomic_t running;

char* get_current_time() {
    static char time_str[64];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return time_str;
}

__attribute__((constructor))
void on_load() {
    printf("\n[%s] *** Библиотека инжектирована в процесс %d! ***\n", get_current_time(), getpid());
    printf("[%s] *** Останавливаю цикл... ***\n", get_current_time());
    fflush(stdout); 
    
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (handle) {
        volatile sig_atomic_t *running_ptr = (volatile sig_atomic_t *)dlsym(handle, "running");
        
        if (running_ptr) {
            *running_ptr = 0;
            printf("[%s] *** Переменная running успешно установлена в 0 ***\n", get_current_time());
            fflush(stdout);
        } else {
            printf("[%s] *** Не удалось найти переменную running: %s ***\n", get_current_time(), dlerror());
            fflush(stdout);
            volatile sig_atomic_t *global_running = &running;
            *global_running = 0;
            printf("[%s] *** Прямая модификация running через внешнюю ссылку ***\n", get_current_time());
            fflush(stdout);
        }
        
        dlclose(handle);
    } else {
        printf("[%s] *** Не удалось получить дескриптор программы: %s ***\n", get_current_time(), dlerror());
        fflush(stdout);
    }
}

__attribute__((destructor))
void on_unload() {
    printf("[%s] *** Библиотека выгружена из процесса %d ***\n", get_current_time(), getpid());
    fflush(stdout);
}