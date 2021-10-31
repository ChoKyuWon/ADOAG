CC := clang
CFI_FLAGS := -fsanitize=cfi-icall -flto -S -emit-llvm
CFLAGS := -g -pie

all:
	$(CC) $(CFLAGS) $(CFI_FLAGS) main.c -o main.s
	objdump -d main.o > main.S

clean:
	rm *.o *.S