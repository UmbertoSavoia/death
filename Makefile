TARGET = Death
PACKER = packer

CC = gcc
CFLAGS = -Werror -Wextra -Werror

AS = nasm
ASFLAGS = -f elf64

RM = rm -f

SRC_C = $(wildcard src/*.c)
SRC_A = $(wildcard src/*.s)
OBJS_C = $(SRC_C:.c=.o)
OBJS_S = $(SRC_A:.s=.o)

all: $(PACKER) $(TARGET)

$(TARGET) : $(OBJS_S)
	ld $^ -o $(TARGET)
	./$(PACKER) $(TARGET)

$(PACKER) : $(OBJS_C)
	$(CC) $(CFLAGS) $^ -o $(PACKER)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.s
	$(AS) $(ASFLAGS) $< -o $@

clean:
	$(RM) $(OBJS_S) $(OBJS_C)

fclean: clean
	$(RM) $(TARGET) $(PACKER)

re: fclean all