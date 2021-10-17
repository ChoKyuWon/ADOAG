CC := clang
CFI_FLAGS := -fsanitize=cfi-icall -flto
CFLAGS := -g -pie

all:
	$(CC) $(CFLAGS) $(CFI_FLAGS) main.c -o main.o
	objdump -d main.o > main.S

clean:
	rm *.o *.S