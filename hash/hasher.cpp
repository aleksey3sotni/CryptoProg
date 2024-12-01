#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <iostream>
#include <fstream>
#include <string>
#include <cryptlib.h>
#include <md5.h>
#include <hex.h>
#include <filters.h>
#include <files.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Невозможно открыть файл!" << std::endl;
        return 1;
    }

    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cout << "Текст из файла: " << content << std::endl;

    
    file.clear();
    file.seekg(0, std::ios::beg);

    
    CryptoPP::Weak::MD5 hash;
    std::string hashResult;
    CryptoPP::FileSource(file, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashResult))
        )
    );

    std::cout << "Текст ХЭШ: " << hashResult << std::endl;
    
    return 0;
}
