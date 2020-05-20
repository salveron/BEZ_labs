GCC = gcc
FLAGS = -Wall -pedantic -g
LDFLAGS = -lcrypto -lssl

all: secure_connection
run:
	./secure_connection
secure_connection: main.c
	$(GCC) $(FLAGS) $< -o $@ $(LDFLAGS)
clean:
	rm secure_connection 2>/dev/null
