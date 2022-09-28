CC=gcc
CFLAGS=-I.
DEPS = bluetooth.h  hci.h  hci_lib.h  oui.h
OBJ = bluetooth.o  hci.o  scanMijia.o  oui.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

scanMijia: $(OBJ)
	$(CC) -O2 -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ core scanMijia 
