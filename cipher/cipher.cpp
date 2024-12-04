#include <iostream>
#include <fstream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <osrng.h>
#include <secblock.h>
#include <hex.h>
#include <sha.h>
#include <files.h>
#include <pwdbased.h> 

using namespace CryptoPP;
using namespace std;

void handleEncryption(const string& pass, const string& input, const string& output) {
    CryptoPP::byte key[SHA256::DIGESTSIZE];
    PKCS12_PBKDF<SHA256> pbkdf;
    CryptoPP::byte salt[AES::BLOCKSIZE];
    AutoSeededRandomPool prng;
    prng.GenerateBlock(salt, sizeof(salt));

    pbkdf.DeriveKey(key, sizeof(key), 0, 
        reinterpret_cast<const CryptoPP::byte*>(pass.data()), pass.size(), 
        salt, sizeof(salt), 1024, 0.0f);

    CryptoPP::byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    ifstream inFile(input, ios::binary);
    ofstream outFile(output, ios::binary);
    
    FileSource(inFile, true, 
        new StreamTransformationFilter(encryptor, 
        new FileSink(outFile)));

    // Save the password
    ofstream passFile("/home/stud/git_belik/CryptoProg/cipher/userPass");
    if (!passFile) {
        cerr << "Ошибка: не удаётся открыть файл userPass для записи." << endl;
        return;
    }
    passFile << pass;
    passFile.close();

    // Save the key
    ofstream keyFile("/home/stud/git_belik/CryptoProg/cipher/Key", ios::binary);
    if (!keyFile) {
        cerr << "Ошибка: не удаётся открыть файл Key для записи." << endl;
        return;
    }
    keyFile.write(reinterpret_cast<const char*>(key), sizeof(key));
    keyFile.close();

    // Save IV
    ofstream ivFile("/home/stud/git_belik/CryptoProg/cipher/fileIV", ios::binary);
    if (!ivFile) {
        cerr << "Ошибка: не удаётся открыть файл fileIV для записи." << endl;
        return;
    }
    ivFile.write(reinterpret_cast<const char*>(iv), sizeof(iv));
    ivFile.close();
}

void handleDecryption(const string& pass, const string& input, const string& output) {
    string storedPass;
    FileSource("/home/stud/git_belik/CryptoProg/cipher/userPass", true, new StringSink(storedPass));

    if (pass != storedPass) {
        cout << "Неправильный пароль\n";
        return;
    }

    CryptoPP::byte key[SHA256::DIGESTSIZE];
    FileSource("/home/stud/git_belik/CryptoProg/cipher/Key", true, new ArraySink(key, sizeof(key)));

    CryptoPP::byte iv[AES::BLOCKSIZE];
    FileSource("/home/stud/git_belik/CryptoProg/cipher/fileIV", true, new ArraySink(iv, sizeof(iv)));

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv);

    ifstream inFile(input, ios::binary);
    ofstream outFile(output, ios::binary);
    
    FileSource(inFile, true, 
        new StreamTransformationFilter(decryptor, 
        new FileSink(outFile)));
}

int main() {
    string operation, pass, input, output;
    cout << "Введите режим зашифровать/расшифровать:" << endl;
    cin >> operation;

    if (operation == "зашифровать") {
        cout << "Создайте пароль:" << endl;
        cin >> pass;
        cout << "Укажите путь к файлу чтения:" << endl;
        cin >> input;
        cout << "Укажите путь к файлу записи:" << endl;
        cin >> output;

        handleEncryption(pass, input, output);
    } else if (operation == "расшифровать") {
        cout << "Введите Пароль:" << endl;
        cin >> pass;
        cout << "Укажите путь к файлу чтения:" << endl;
        cin >> input;
        cout << "Укажите путь к файлу записи:" << endl;
        cin >> output;

        handleDecryption(pass, input, output);
    } else {
        cerr << "Ошибка: неправильный режим - " << operation << endl;
        return 1;
    }

    return 0;
}
