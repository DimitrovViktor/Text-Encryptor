#include <iostream>
#include <string>
#include "argon/argon2.h"

std::string encryptor(std::string encrKey, std::string normText);

void hashings(std::string encrPass) {
    const char* charKey = encrPass.c_str();
    const char* salt = "100_200_Salting"; // I will most likely also allow users to add custom salt
    // can also add peppering
    char hash[32];
    char encoded[128];
    int result = argon2_hash(
        2,
        1 << 16,
        1,
        charKey, strlen(charKey),
        salt, strlen(salt),
        hash, sizeof(hash),
        encoded, sizeof(encoded),
        Argon2_id,
        ARGON2_VERSION_13
    );

    if (result == ARGON2_OK) {
        std::cout << "(encryption key info)encoded: " << encoded << std::endl;
    }
    else {
        std::cout << "hash failed: " << argon2_error_message(result) << std::endl;
    }
}

int main()
{
    std::string encrKey;
    std::string normText;
    std::string encrText;

    char hash[32];
    char encoded[128];

    std::cout << "Enter password:\n";
    std::getline(std::cin, encrKey);

    std::cout << "Enter text:\n";
    std::getline(std::cin,normText);

    const char* charKey = normText.c_str();

    encrText = encryptor(encrKey, normText);

    std::cout << "test text:\n" << encrText << "\n";
    

    hashings(normText);

    std::getline(std::cin, encrText);
}

std::string encryptor(std::string encrKey, std::string normText) {
    std::string encrText;

    encrText = normText /*+ encryption*/;

    return encrText;
}
