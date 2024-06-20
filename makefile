# Define variables
ASM = uasm64
LINK = link

ASMFLAGS = -q -win64 -I"./include"
LINKFLAGS = /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:callisto.exe /LIBPATH:./lib kernel32.lib Ws2_32.lib ntdll.lib

# Default target
all: callisto.exe

# Rule to assemble .asm file
callisto.obj: src/callisto.asm
	$(ASM) $(ASMFLAGS) src/callisto.asm

# Rule to link object files
callisto.exe: callisto.obj
	$(LINK) $(LINKFLAGS) callisto.obj

# Clean target
clean:
	del *.obj *.exe
