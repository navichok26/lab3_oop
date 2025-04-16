#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    printf("Получен сигнал: %d\n", sig);
    running = 0;
}

int main() {
    printf("PID программы: %d\n", getpid());
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
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