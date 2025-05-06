#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

volatile sig_atomic_t running = 1;

int enable_traceme() {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        if (errno == EPERM) {
            return 1;
        }
    } else {
        ptrace(PTRACE_DETACH, 0, 0, 0);
    }

    return 0;
}

void disable_debugger() {
    static time_t last_check = 0;
    time_t now = time(NULL);

    if (now - last_check >= 2) {
        last_check = now;

        if (enable_traceme()) {
            printf("\n!!! Обнаружена попытка отладки! Завершение работы !!!\n");
            fflush(stdout);
            exit(1);
        }
    }
}

void handle_signal(int sig) {
    printf("Получен сигнал: %d\n", sig);
    running = 0;
}

int main() {
    printf("PID программы: %d\n", getpid());

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    disable_debugger();

    int counter = 1;

    while (running) {
        printf("Текущее число: %d из 20\n", counter);
        fflush(stdout);

        sleep(1);

        counter++;
        if (counter > 20) {
            counter = 1;
            printf("--------- Начинаем новый цикл ---------\n");
        }
    }

    printf("Программа завершена\n");
    return 0;
}
