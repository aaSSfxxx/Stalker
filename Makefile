CC=mingw32-gcc
FLAGS=-Wall -nostdlib -g -I$(CURDIR)/include

all: stalker.exe trace.dll
	@echo "Build completed"

stalker-gui: stalker/stalker-gui.o
	windres stalker/stalker-gui.rc stalker/stalker-res.o
	$(CC) -o stalker-gui.exe stalker/stalker-gui.o stalker/stalker-res.o -lcomdlg32 -lshell32

stalker.exe: stalker/stalker.o stalker/functions.o
	$(CC) -o stalker.exe stalker/stalker.o stalker/functions.o

trace.dll: dll/trace.o dll/pe_utils.o dll/hook.o
	$(CC) -shared -o trace.dll dll/trace.o dll/pe_utils.o dll/hook.o
	
%.o: %.c
	$(CC) $(FLAGS) -c -o $@ $^

clean:
	del dll\*.o
	del stalker\*.o
