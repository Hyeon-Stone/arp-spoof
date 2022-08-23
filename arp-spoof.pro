TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    arphdr.cpp \
    ethhdr.cpp \
    kbctrl.cpp \
    send.cpp

HEADERS += \
    arphdr.h \
    ethhdr.h \
    kbctrl.h \
    send.h
