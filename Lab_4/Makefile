GCC = gcc
FLAGS = -Wall -pedantic -g
LDFLAGS = -lcrypto

all: rsa-encrypter rsa-decrypter
run:
	# ENCRYPTING INPUT FILE
	./rsa-encrypter input.gif pubkey.pem AES-128-CBC
	# DECRYPTING INPUT FILE
	./rsa-decrypter rsa-encrypted privkey.pem
	diff input.gif rsa-decrypted.gif
	# FILES ARE THE SAME --> ENCRYPTED AND DECRYPTED WELL
rsa-encrypter: rsa-encrypter.c
	$(GCC) $(FLAGS) $< -o $@ $(LDFLAGS)
rsa-decrypter: rsa-decrypter.c
	$(GCC) $(FLAGS) $< -o $@ $(LDFLAGS)
clean:
	rm rsa-encrypter rsa-decrypter rsa-encrypted rsa-decrypted.gif 2>/dev/null
