compileStartFile:
	nasm -f win64 m.nasm -o math.o
	x86_64-w64-mingw32-ld math.o -o win.exe -e _start -lkernel32 --subsystem console