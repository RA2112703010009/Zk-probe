CC = gcc
CFLAGS = -g -O2
LIBS = -lbpf -lelf

all: execve_loader

execve_loader: execve_loader.c
	$(CC) $(CFLAGS) execve_loader.c -o execve_loader $(LIBS)

clean:
	rm -f execve_loader
