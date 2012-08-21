CC=mingw32-gcc
FLAGS=-Wall -nostdlib -g -I$(CURDIR)/include

all: stalker.exe trace.dll
	@echo "Build completed"

stalker.exe: stalker/stalker.o stalker/functions.o
	$(CC) -o stalker.exe stalker/stalker.o stalker/functions.o

trace.dll: dll/trace.o dll/pe_utils.o dll/hook.o
	$(CC) -shared -o trace.dll dll/trace.o dll/pe_utils.o dll/hook.o
	
%.o: %.c
	$(CC) $(FLAGS) -c -o $@ $^

clean:
	del dll\*.o
	del stalker\*.o