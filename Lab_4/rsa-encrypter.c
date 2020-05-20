// Authored by Nikita Mortuzaiev (mortunik)

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

typedef unsigned char BYTE;
const unsigned long BLOCK_SIZE = 4096;


int main(int argc, char * argv []) {
    if (argc != 4){
        perror("Usage: ./rsa-encrypter <input file name> <public key file name> <symmetric cipher name>\n");
        return 1;
    }

    // Opening input and output files
    FILE * in = fopen(argv[1], "rb");
    const char * outfile_name = "rsa-encrypted";
    FILE * out = fopen(outfile_name, "wb");
    if (!in || !out){
        perror("Error opening files.\n");
        return 2;
    }

    // Reading the public key
    FILE * pkfp = fopen(argv[2], "rb");
    if (!pkfp){
        perror("Invalid public key file name.\n");
        return 3;
    }
    EVP_PKEY * pubkey = PEM_read_PUBKEY(pkfp, NULL, NULL, NULL);

    // Adding all ciphers and seeding the random number generator
    OpenSSL_add_all_ciphers();
    if (RAND_load_file("/dev/random", 32) != 32) {
        perror("Can't seed the random number generator.\n");
        return 4;
    }

    // Setting up the context and the cipher type
    EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new();
    if (!context) return 5;
    int sym_key_len = EVP_PKEY_size(pubkey);
    BYTE * sym_key = malloc(sym_key_len);
    BYTE iv [EVP_MAX_IV_LENGTH];
    const char * sym_cipher_name = argv[3];
    const EVP_CIPHER * sym_cipher_type = EVP_get_cipherbyname(sym_cipher_name);
    if(!sym_cipher_type) {
        printf("Cipher %s doesn't exist.\n", sym_cipher_name);
        return 6;
    }

    // Getting the code for each supported cipher
    unsigned sym_cipher_code;
    if (!strcmp(sym_cipher_name, "AES-128-CBC"))
        sym_cipher_code = 0;
    else if (!strcmp(sym_cipher_name, "AES-256-CBC"))
        sym_cipher_code = 1;
    else if (!strcmp(sym_cipher_name, "DES-CBC"))
        sym_cipher_code = 2;
    else if (!strcmp(sym_cipher_name, "DES-ECB"))
        sym_cipher_code = 3;
    else return 7;

    if (!EVP_SealInit(context, sym_cipher_type, &sym_key, &sym_key_len, iv, &pubkey, 1)) return 8;

    // Writing the cipher code and the key length
    unsigned tmp = sym_cipher_code;
    for (unsigned i = 0; i < 4; i++){
        BYTE byte = (BYTE)(tmp & 0xffu);
        fwrite(&byte, sizeof(BYTE), 1, out);
        tmp >>= 8u;
    }
    tmp = sym_key_len;
    for (unsigned i = 0; i < 4; i++){
        BYTE byte = (BYTE)(tmp & 0xffu);
        fwrite(&byte, sizeof(BYTE), 1, out);
        tmp >>= 8u;
    }
    // Writing the key and iv
    fwrite(sym_key, sizeof(BYTE), sym_key_len, out);
    fwrite(iv, sizeof(BYTE), EVP_MAX_IV_LENGTH, out);

    BYTE * buffer = malloc(BLOCK_SIZE);
    unsigned buffer_len;
    BYTE * out_buffer = malloc(2 * BLOCK_SIZE);
    int out_buffer_len;

    // Encrypting by blocks of size BLOCK_SIZE and writing to the output file
    while ((buffer_len = fread(buffer, sizeof(BYTE), BLOCK_SIZE, in)) > 0){
        if (EVP_SealUpdate(context, out_buffer, &out_buffer_len, buffer, buffer_len) != 1)
            return 9;
        fwrite(out_buffer, sizeof(BYTE), out_buffer_len, out);
    }

    if (EVP_SealFinal(context, out_buffer, &out_buffer_len) != 1)
        return 10;
    fwrite(out_buffer, sizeof(BYTE), out_buffer_len, out);

    // Cleaning up
    free(out_buffer);
    free(buffer);
    free(sym_key);
    EVP_CIPHER_CTX_free(context);
    EVP_PKEY_free(pubkey);
    fclose(pkfp);
    fclose(in);
    fclose(out);

    return 0;
}
