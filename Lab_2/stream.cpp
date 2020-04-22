#include <iostream>
#include <cstdlib>
#include <cstring>
#include <openssl/evp.h>
using namespace std;

const unsigned char PUBLIC_MESSAGE [1024] = "abcdefghijklmnopqrstuvwxyz0123";

int my_encryption(){
    const unsigned char my_secret_message [1024] = "Stay home during the quarantine.";
    unsigned char my_secret_cipher [1024];
    unsigned char my_public_cipher [1024];
    int secret_ct_len = 0, public_ct_len = 0;

    const unsigned char my_secret_key [EVP_MAX_KEY_LENGTH] = "b2hn0ko9332";
    unsigned char my_initial_vector [EVP_MAX_IV_LENGTH] = "d03283746523dfa";

    const string cipher_name = "RC4";
    const EVP_CIPHER * cipher_type;

    OpenSSL_add_all_ciphers();
    cipher_type = EVP_get_cipherbyname(cipher_name.c_str());
    if(!cipher_type) {
        cout << " --> Cipher " << cipher_name << " doesn't exist." << endl;
        return 1;
    }

    EVP_CIPHER_CTX * context;
    context = EVP_CIPHER_CTX_new();
    if (context == nullptr)
        return 2;

    int res, tmp_secret_ct_len;
    // Encrypting my secret message
    res = EVP_EncryptInit_ex(context, cipher_type, nullptr, my_secret_key, my_initial_vector);
    if(res != 1) return 3;
    res = EVP_EncryptUpdate(context, my_secret_cipher, &tmp_secret_ct_len, my_secret_message, strlen((const char *) my_secret_message));
    if(res != 1) return 4;
    secret_ct_len += tmp_secret_ct_len;
    res = EVP_EncryptFinal_ex(context, my_secret_cipher + secret_ct_len, &tmp_secret_ct_len);
    if(res != 1) return 5;
    secret_ct_len += tmp_secret_ct_len;

    int tmp_public_ct_len;
    //Encrypting my public message
    res = EVP_EncryptInit_ex(context, cipher_type, nullptr, my_secret_key, my_initial_vector);
    if(res != 1) return 6;
    res = EVP_EncryptUpdate(context, my_public_cipher, &tmp_public_ct_len, PUBLIC_MESSAGE, strlen((const char *) PUBLIC_MESSAGE));
    if(res != 1) return 7;
    public_ct_len += tmp_public_ct_len;
    res = EVP_EncryptFinal_ex(context, my_public_cipher + public_ct_len, &tmp_public_ct_len);
    if(res != 1) return 8;
    public_ct_len += tmp_public_ct_len;

    EVP_CIPHER_CTX_free(context);

    cout << " --> My public message cipher in bytes: ";
    for (int i = 0; i < public_ct_len; i++)
        printf("%02x", my_public_cipher[i]);
    cout << endl << " --> My secret message cipher in bytes: ";
    for (int i = 0; i < secret_ct_len; i++)
        printf("%02x", my_secret_cipher[i]);
    cout << endl;

    return 0;
}

int main(int argc, char * argv []) {
    if (argc != 3){
        cout << " --> Usage: <public message cipher> <secret message cipher>." << endl;
        return -1;
    }

    cout << " --> The initial vector has no influence on the cipher text." << endl
         << " --> We can change it how we want, but the decrypted text will stay the same." << endl << endl;

    if (my_encryption())
        return -2;

    const string rcv_public_ct (argv[1]);
    const string rcv_secret_ct (argv[2]);
    unsigned char rcv_public_ct_bytes [1024];
    unsigned char rcv_secret_ct_bytes [1024];
    unsigned rcv_public_bytes_len = rcv_public_ct.length() / 2;
    unsigned rcv_secret_bytes_len = rcv_secret_ct.length() / 2;

    // Converting hex strings into byte arrays
    cout << endl << " --> Received public message in bytes: ";
    for (unsigned i = 0; i < rcv_public_ct.length(); i += 2){
        string byte_string = rcv_public_ct.substr(i, 2);
        rcv_public_ct_bytes[i / 2] = (char)strtol(byte_string.c_str(), nullptr, 16);
        printf("%02x", rcv_public_ct_bytes[i / 2]);
    }
    cout << endl << " --> Received secret message in bytes: ";
    for (unsigned i = 0; i < rcv_secret_ct.length(); i += 2){
        string byte_string = rcv_secret_ct.substr(i, 2);
        rcv_secret_ct_bytes[i / 2] = (char)strtol(byte_string.c_str(), nullptr, 16);
        printf("%02x", rcv_secret_ct_bytes[i / 2]);
    }
    cout << endl;

    // Decrypting the message
    unsigned char tmp_string [1024];
    unsigned char decrypted [1024];
    unsigned tmp_string_len = rcv_public_bytes_len > rcv_secret_bytes_len
                            ? rcv_secret_bytes_len
                            : rcv_public_bytes_len;

    for (unsigned i = 0; i < tmp_string_len; i++)
        tmp_string[i] = (rcv_public_ct_bytes[i] ^ rcv_secret_ct_bytes[i]) % 256;

    for (unsigned i = 0; i < tmp_string_len; i++)
        decrypted[i] = (tmp_string[i] ^ PUBLIC_MESSAGE[i]) % 256;

    cout << endl << " --> Public message was: \"" << PUBLIC_MESSAGE << "\"" << endl << " --> Secret message was: \"";
    for (unsigned i = 0; i < tmp_string_len; i++)
        printf("%c", decrypted[i]);
    cout << "\"" << endl;

    return 0;
}

