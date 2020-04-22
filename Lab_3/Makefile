G++ = g++
FLAGS = -Wall -pedantic
LDFLAGS = -lcrypto

all: encrypter
run:
	./encrypter -e ecb Mad_scientist.bmp
	./encrypter -d ecb Mad_scientist_ecb.bmp
	diff Mad_scientist.bmp Mad_scientist_ecb_dec.bmp
	# --> FILES ARE THE SAME --> Encrypted and decrypted well
	./encrypter -e cbc Mad_scientist.bmp
	./encrypter -d cbc Mad_scientist_cbc.bmp
	diff Mad_scientist.bmp Mad_scientist_cbc_dec.bmp
	# --> FILES ARE THE SAME --> Encrypted and decrypted well
	./encrypter -e ecb homer-simpson.bmp
	./encrypter -d ecb homer-simpson_ecb.bmp
	diff homer-simpson.bmp homer-simpson_ecb_dec.bmp
	# --> FILES ARE THE SAME --> Encrypted and decrypted well
	./encrypter -e cbc homer-simpson.bmp
	./encrypter -d cbc homer-simpson_cbc.bmp
	diff homer-simpson.bmp homer-simpson_cbc_dec.bmp
	# --> FILES ARE THE SAME --> Encrypted and decrypted well
encrypter: encrypter.cpp
	$(G++) $(FLAGS) $< -o $@ $(LDFLAGS)