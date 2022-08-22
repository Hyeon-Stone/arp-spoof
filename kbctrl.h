#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>

void InitKb();

void CloseKb();

int KbCtrl();
