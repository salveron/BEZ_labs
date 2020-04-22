#include <iostream>
#include <string>
#include <openssl/evp.h>
using namespace std;

int main(int argc, char * argv []){

    const string hash_name = "sha256";
    const EVP_MD * hash_type;

    OpenSSL_add_all_digests();
    hash_type = EVP_get_digestbyname(hash_name.c_str());
    if(!hash_type) {
        cout << " --> Hash function " << hash_name << " doesn't exist." << endl;
        return 1;
    }

    EVP_MD_CTX * context;
    context = EVP_MD_CTX_create();
    if(context == nullptr)
        return 2;

    unsigned char text[4];
    unsigned char output_hash[EVP_MAX_MD_SIZE];
    int hash_len;

    for (uint32_t i = 0; i < UINT32_MAX; i++){
        for (unsigned j = 0; j < 4; j++)
            text[j] = (unsigned char)((i >> ((3 - j) * 8)) & 0xffu);

        int res;
        res = EVP_DigestInit_ex(context, hash_type, nullptr);
        if(res != 1) return 3;
        res = EVP_DigestUpdate(context, text, 4);
        if(res != 1) return 4;
        res = EVP_DigestFinal_ex(context, output_hash, (unsigned int *) &hash_len);
        if(res != 1) return 5;

        // Uncomment this code to see the process of searching
        /* cout << hex << i << " - ";
        for(unsigned char x : text)
            printf("%02x ", x);
        cout << " - ";
        for(int j = 0; j < hash_len; j++)
            printf("%02x", output_hash[j]);
        cout << endl; */

        if (output_hash[0] == (unsigned char)0xaa
         && output_hash[1] == (unsigned char)0xbb)
            break;
    }

    EVP_MD_CTX_destroy(context);

    cout << " --> Found text \"";
    for (unsigned char i : text)
        printf("%c", i);
    cout << "\"\n\twith byte representation: ";
    for (unsigned char i : text)
        printf("%02x ", i);
    cout << "\n\twith hash: ";
    for (int i = 0; i < hash_len; i++)
        printf("%02x", output_hash[i]);
    cout << endl << endl;

    return 0;
}