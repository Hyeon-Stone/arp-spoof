#include "kbctrl.h"

static struct termios InitTio, NewTio;

static int peek_character = -1;

void InitKb(){
    tcgetattr(0,&InitTio);
    NewTio = InitTio;
    NewTio.c_lflag &= ~ICANON; //--> https://pubs.opengroup.org/onlinepubs/7908799/xbd/termios.html#tag_008_001_007
    NewTio.c_lflag &= ~ECHO; // Turn off Print about KeyBoard Input
    NewTio.c_cc[VMIN] = 1; // Minimum Inout Buf
    NewTio.c_cc[VTIME] = 0; // Clear Time to reset buf
    tcsetattr(0, TCSANOW, &NewTio);
}

void CloseKb(){
    tcsetattr(0, TCSANOW, &InitTio);
}

int KbCtrl(){
    unsigned char ch;
    int nread;

    if (peek_character != -1) return 1;
    NewTio.c_cc[VMIN]=0;
    tcsetattr(0, TCSANOW, &NewTio);
    nread = read(0,&ch,1);
    NewTio.c_cc[VMIN]=1;
    tcsetattr(0, TCSANOW, &NewTio);
    if(nread == 1)
    {
        peek_character = ch;
        return 1;
    }
    return 0;
}
