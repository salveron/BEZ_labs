G++ = g++
FLAGS = -Wall -pedantic
LDFLAGS = -lcrypto

all: hash stream
run:
	./hash
	./stream 8f519eef9b407839cebe485df0065ae5fc9b a71391e488433f34c9b75148ed1c5cfbeac78413648d5d953b1a1f956f99
hash: hash.cpp
	$(G++) $(FLAGS) $< -o $@ $(LDFLAGS)
stream: stream.cpp
	$(G++) $(FLAGS) $< -o $@ $(LDFLAGS)