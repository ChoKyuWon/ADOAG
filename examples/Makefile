CC := clang
CFI_FLAGS := -fsanitize=cfi-icall -flto
CFLAGS := -g -pie

all:
	$(CC) $(CFLAGS) $(CFI_FLAGS) main.c -o main.o
