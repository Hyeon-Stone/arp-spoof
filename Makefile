LDLIBS=-lpcap -lpthread

all: arp-spoof

arphdr.o: arphdr.h arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp

kbctrl.o: kbctrl.h kbctrl.cpp

send.o: ethhdr.h arphdr.h send.h send.cpp kbctrl.h

arp-spoof: main.o arphdr.o ethhdr.o send.o kbctrl.o
	$(LINK.cc)  $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o
clean:
	rm -f arp-spoof *.o

