// Authored by Nikita Mortuzaiev (mortunik)

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

typedef unsigned char BYTE;
const unsigned int BLOCK_SIZE = 4096;


int main(int argc, char * argv []) {
    if (argc != 3){
        perror("Usage: ./rsa-decrypter <encrypted file name> <private key file name>\n");
        return 1;
    }

    // Opening input and output files
    FILE * in = fopen(argv[1], "rb");
    const char * outfile_name = "rsa-decrypted.gif";
    FILE * out = fopen(outfile_name, "wb");
    if (!in || !out){
        perror("Invalid input file name.\n");
        return 2;
    }

    // Reading the private key
    FILE * pkfp = fopen(argv[2], "rb");
    if (!pkfp){
        perror("Invalid private key file name.\n");
        return 3;
    }
    EVP_PKEY * privkey = PEM_read_PrivateKey(pkfp, NULL, NULL, NULL);

    // Adding all ciphers and seeding the random number generator
    OpenSSL_add_all_ciphers();
    if (RAND_load_file("/dev/random", 32) != 32) {
        perror("Can't seed the random number generator.\n");
        return 4;
    }

    // Setting up the context
    EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new();
    if (!context) return 5;

    // Reading the cipher code and the key length from the file
    BYTE bytes [4];
    fread(bytes, sizeof(BYTE), 4, in);
    unsigned sym_cipher_code = 0, multiplier = 1;
    for (unsigned i = 0; i < 4; i++){
        sym_cipher_code += bytes[i] * multiplier;
        multiplier *= 0x100;
    }
    fread(bytes, sizeof(BYTE), 4, in);
    unsigned sym_key_len = 0; multiplier = 1;
    for (unsigned i = 0; i < 4; i++){
        sym_key_len += bytes[i] * multiplier;
        multiplier *= 0x100;
    }

    // Reading the key and the iv from the file
    BYTE * sym_key = malloc(sym_key_len + 1);
    BYTE iv [EVP_MAX_IV_LENGTH];
    fread(sym_key, sizeof(BYTE), sym_key_len, in);
    fread(iv, sizeof(BYTE), EVP_MAX_IV_LENGTH, in);

    // Setting the cipher name by its code
    char sym_cipher_name [12];
    if (sym_cipher_code == 0){
        strncpy(sym_cipher_name, "AES-128-CBC", 11);
        sym_cipher_name[11] = '\0';
    } else if (sym_cipher_code == 1){
        strncpy(sym_cipher_name, "AES-256-CBC", 11);
        sym_cipher_name[11] = '\0';
    } else if (sym_cipher_code == 2) {
        strncpy(sym_cipher_name, "DES-CBC", 7);
        sym_cipher_name[7] = '\0';
    } else if (sym_cipher_code == 3) {
        strncpy(sym_cipher_name, "DES-ECB", 7);
        sym_cipher_name[7] = '\0';
    } else return 7;

    // Setting up the cipher type
    const EVP_CIPHER * sym_cipher_type = EVP_get_cipherbyname(sym_cipher_name);
    if(!sym_cipher_type) {
        printf("Cipher %s doesn't exist.\n", sym_cipher_name);
        return 6;
    }

    if (!EVP_OpenInit(context, sym_cipher_type, sym_key, (int)sym_key_len, iv, privkey)) return 7;

    BYTE * buffer = malloc(BLOCK_SIZE);
    unsigned buffer_len;
    BYTE * out_buffer = malloc(2 * BLOCK_SIZE);
    int out_buffer_len;

    // Decrypting by blocks of size BLOCK_SIZE and writing to the output file
    while ((buffer_len = fread(buffer, sizeof(BYTE), BLOCK_SIZE, in)) > 0){
        if (EVP_OpenUpdate(context, out_buffer, &out_buffer_len, buffer, buffer_len) != 1)
            return 8;
        fwrite(out_buffer, sizeof(BYTE), out_buffer_len, out);
    }

    if (EVP_OpenFinal(context, out_buffer, &out_buffer_len) != 1)
        return 9;
    fwrite(out_buffer, sizeof(BYTE), out_buffer_len, out);

    // Cleaning up
    free(out_buffer);
    free(buffer);
    free(sym_key);
    EVP_CIPHER_CTX_free(context);
    EVP_PKEY_free(privkey);
    fclose(pkfp);
    fclose(in);
    fclose(out);

    return 0;
}
