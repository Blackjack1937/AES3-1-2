CC = gcc
CFLAGS = -O2 -std=c11 -Wall -Wextra
SRCS = main_q2.c main_attack.c aes-128_enc.c
OBJS = $(SRCS:.c=.o)

# Main convenient targets
.PHONY: all q2 q3 attack test clean

all: attack

# Build the small test used in Q2 (key-schedule inversion tests)
q2: main_q2.o aes-128_enc.o
	$(CC) $(CFLAGS) -o q2 main_q2.o aes-128_enc.o

# Build the attack program (Q3)
attack: main_attack.o aes-128_enc.o
	$(CC) $(CFLAGS) -o attack main_attack.o aes-128_enc.o

# Generic object rules
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Test: build & run the q2 validation
test: q2
	./q2

clean:
	rm -f *.o q2 attack