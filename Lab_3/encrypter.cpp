// Authored by Nikita Mortuzaiev (mortunik)

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>

using namespace std;
typedef unsigned char BYTE;

const BYTE START_BYTES [] = "BM";
const unsigned int FILE_SIZE_POS = 2;
const unsigned int FILE_SIZE_LEN = 4;
const unsigned int RESERVED_BYTES_POS = FILE_SIZE_POS + FILE_SIZE_LEN;
const unsigned int RESERVED_BYTES_LEN = 4;
const unsigned int START_OF_IMG_DATA_POS = RESERVED_BYTES_POS + RESERVED_BYTES_LEN;
const unsigned int START_OF_IMG_DATA_LEN = 4;
const unsigned int IMG_INFO_START_POS = START_OF_IMG_DATA_POS + START_OF_IMG_DATA_LEN;

const unsigned int BLOCK_SIZE = 8;

int process_header(const vector <BYTE> & buffer, unsigned & start_of_img_data){
    if (buffer.size() <= IMG_INFO_START_POS){
        cout << "Invalid header of the input file." << endl;
        return 1;
    }

    int multiplier = 1;
    unsigned file_size = 0;
    for (unsigned i = FILE_SIZE_POS; i < FILE_SIZE_POS + FILE_SIZE_LEN; i++){
        file_size += buffer[i] * multiplier;
        multiplier *= 0x100;
    }

    if (file_size != buffer.size()){
        cout << "Actual file size doesn't match the found one." << endl;
        return 2;
    }

    multiplier = 1;
    start_of_img_data = 0;
    for (unsigned i = START_OF_IMG_DATA_POS; i < START_OF_IMG_DATA_POS + START_OF_IMG_DATA_LEN; i++){
        start_of_img_data += buffer[i] * multiplier;
        multiplier *= 0x100;
    }

    if (file_size <= start_of_img_data){
        cout << "Invalid input file." << endl;
        return 3;
    }

    return 0;
}

int encrypt_decrypt(const BYTE * data, int data_len, bool flag, const string & mode, BYTE * processed, int & processed_len){
    const BYTE key [] = "an1id6732jcs7ue";
    const BYTE iv [] = "s0ni28k30dfk1h";

    const EVP_CIPHER * cipher_type;
    char cipher_name [1024];
    if (mode == "ecb") strcpy(cipher_name, "DES-ECB");
    else               strcpy(cipher_name, "DES-CBC");

    OpenSSL_add_all_ciphers();

    cipher_type = EVP_get_cipherbyname(cipher_name);
    if(!cipher_type) {
        cout << "Cipher " << cipher_name << " doesn't exist." << endl;
        return 1;
    }

    EVP_CIPHER_CTX * context;
    context = EVP_CIPHER_CTX_new();
    if (context == nullptr) return 2;

    processed_len = 0;
    int res, tmp_processed_len;

    if (flag) res = EVP_EncryptInit_ex(context, cipher_type, nullptr, key, iv);
    else      res = EVP_DecryptInit_ex(context, cipher_type, nullptr, key, iv);
    if(res != 1) return 3;

    if (data_len % BLOCK_SIZE == 0)
        EVP_CIPHER_CTX_set_padding(context, 0);

    const BYTE * data_ptr = data;
    BYTE * processed_ptr = processed;

    for (int i = 0; i < (int)(data_len / BLOCK_SIZE); i++){
        if (flag) res = EVP_EncryptUpdate(context, processed_ptr, &tmp_processed_len, data_ptr, BLOCK_SIZE);
        else      res = EVP_DecryptUpdate(context, processed_ptr, &tmp_processed_len, data_ptr, BLOCK_SIZE);
        if(res != 1) return 4;

        data_ptr += BLOCK_SIZE;
        processed_ptr += tmp_processed_len;
        processed_len += tmp_processed_len;
    }

    if (flag) res = EVP_EncryptFinal_ex(context, processed_ptr, &tmp_processed_len);
    else      res = EVP_DecryptFinal_ex(context, processed_ptr, &tmp_processed_len);
    if(res != 1) return 5;
    processed_len += tmp_processed_len;

    EVP_CIPHER_CTX_free(context);

    return 0;
}

void write_output(ofstream & out, const vector <BYTE> & buffer, unsigned start_of_img_data, const BYTE * processed, unsigned processed_len){
    unsigned output_file_size = start_of_img_data + processed_len;

    out << START_BYTES;
    for (unsigned i = 0; i < FILE_SIZE_LEN; i++){
        out << (BYTE)(output_file_size & 0xffu);
        output_file_size >>= 8u;
    }

    for (unsigned i = RESERVED_BYTES_POS; i < start_of_img_data; i++)
        out << buffer[i];

    for (unsigned i = 0; i < processed_len; i++)
        out << processed[i];
}

int main(int argc, char * argv []){
    if (argc != 4){
        cout << "Usage: <encrypt/decrypt flag> <DES mode> <picture name>" << endl;
        return 1;
    }

    if (string(argv[1]) != "-e" && string(argv[1]) != "-d"){
        cout << "Invalid decryption flag. Usage: <-e/-d>" << endl;
        return 2;
    } else if (string(argv[2]) != "ecb" && string(argv[2]) != "cbc"){
        cout << "Invalid DES encryption mode. Usage: <ecb/cbc>" << endl;
        return 3;
    }

    bool flag = (string(argv[1]) == "-e"); // encrypt = true, decrypt = false
    string mode (argv[2]);

    string input_img_name (argv[3]);
    if (flag && input_img_name.substr(input_img_name.length() - 4, 4) != ".bmp"){
        cout << "Invalid input file format to encrypt." << endl;
        return 4;
    } else if (!flag && input_img_name.substr(input_img_name.length() - 8, 8) != ("_" + mode + ".bmp")){
        cout << "Invalid input file format to decrypt." << endl;
        return 5;
    }

    string output_img_name;
    if (flag)
        output_img_name = input_img_name.substr(0, input_img_name.length() - 4) + "_" + mode;
    else
        output_img_name = input_img_name.substr(0, input_img_name.length() - 8) + "_" + mode + "_dec";
    output_img_name += ".bmp";

    ifstream in (input_img_name, ios::in | ios::binary);
    ofstream out (output_img_name, ios::out | ios::binary);
    vector <BYTE> buffer;

    copy (istreambuf_iterator <char> (in), istreambuf_iterator <char> (), back_inserter(buffer));

    unsigned start_of_img_data;
    int return_value = process_header(buffer, start_of_img_data);
    if (return_value){
        cout << "Header processing failed." << endl;
        return 6;
    }

    BYTE * processed = new BYTE [buffer.size() + BLOCK_SIZE + 1];
    int processed_len;

    cout << "------------------------------------------------------------------------------" << endl;
    cout << (flag ? "Encrypting" : "Decrypting") << " file \"" << input_img_name << "\"..." << endl;

    return_value = encrypt_decrypt(buffer.data() + start_of_img_data,
                                   (int)(buffer.size() - start_of_img_data),
                                   flag,
                                   mode,
                                   processed,
                                   processed_len);
    if (return_value){
        cout << "Encryption or decryption failed with code " << return_value << endl;
        delete [] processed;
        return 7;
    }

    write_output(out, buffer, start_of_img_data, processed, processed_len);
    cout << "Done. Output written to the file \"" << output_img_name << "\"" << endl;
    cout << "------------------------------------------------------------------------------" << endl;

    in.close();
    out.close();

    delete [] processed;
    return 0;
}

