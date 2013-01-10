CC=mingw32-gcc
FLAGS=-Wall -nostdlib -g -I$(CURDIR)/include

all: stalker.exe trace.dll stalker-gui.exe
	@echo Build completed

stalker-gui.exe: stalker/stalker-gui.o stalker/functions.o stalker/stalker-gui.obj
	$(CC) -o stalker-gui.exe stalker/stalker-gui.o stalker/functions.o stalker/stalker-gui.obj -lcomdlg32 -lshell32

stalker.exe: stalker/stalker.o stalker/functions.o stalker/stalker-gui.obj
	$(CC) -o stalker.exe stalker/stalker.o stalker/functions.o stalker/stalker-gui.obj

trace.dll: dll/trace.o dll/pe_utils.o dll/hook.o
	$(CC) -shared -o trace.dll dll/trace.o dll/pe_utils.o dll/hook.o
	
%.o: %.c
	$(CC) $(FLAGS) -c -o $@ $^

%.obj: %.rc
	windres $^ $@

clean:
	del dll\*.o
	del stalker\*.o