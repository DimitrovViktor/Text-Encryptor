#include <iostream>
#include <string>
#include <vector>

#include "argon/argon2.h"

#include "libsodium/sodium.h"

std::vector<unsigned char> hashings(std::string encrPass);

std::string encryptor(std::string encrKey, std::string normText, std::vector<unsigned char> hash);

std::string getHash(const char* encoded);

std::string decryptor(std::string encrKey, std::string encrText, std::vector<unsigned char> hash);

int main()
{
    if (sodium_init() < 0) {
        std::cout << "sodium didn't load";
    }
    std::string encrKey;

    std::string normText;
    std::string encrText;
    std::string decrText;

    std::string hashPass;

    // Get password
    std::cout << "Enter password:\n";
    std::getline(std::cin, encrKey);

    // Get password hash
    std::vector<unsigned char> hash = hashings(encrKey);


    // Get text to encrypt
    std::cout << "Enter text:\n";
    std::getline(std::cin, normText);

    const char* charKey = normText.c_str();

    // Encrypt text
    encrText = encryptor(encrKey, normText, hash);

    // Print encrypted text
    std::cout << "encrypted text:\n" << encrText << "\n";

    decrText = decryptor(encrKey, encrText, hash);

    std::cout << "decrypted text:\n" << decrText << "\n";


    std::getline(std::cin, encrText);
}

std::vector<unsigned char> hashings(std::string encrPass) {
    const char* charKey = encrPass.c_str();
    const char* salt = "100_200_Salting"; // I will most likely also allow users to add custom salt
    // can also add peppering
    std::vector<unsigned char> hash(crypto_secretbox_KEYBYTES);
    char encoded[128];
    int result = argon2_hash(
        2,
        1 << 16,
        1,
        charKey, strlen(charKey),
        salt, strlen(salt),
        hash.data(), hash.size(),
        encoded, sizeof(encoded),
        Argon2_id,
        ARGON2_VERSION_13
    );

    if (result == ARGON2_OK) {
        std::cout << "[INFO] encoded: " << encoded << std::endl;
        std::string hashOnly = getHash(encoded);
        std::cout << "[INFO] Extracted hash: " << hashOnly << std::endl;
    }
    else {
        std::cout << "hash failed: " << argon2_error_message(result) << std::endl;
    }
    return hash;
}

std::string getHash(const char* encoded) {
    std::string encodedStr(encoded);
    size_t lastDollar = encodedStr.rfind('$');
    if (lastDollar == std::string::npos || lastDollar + 1 >= encodedStr.length()) {
        return "";
    }
    return encodedStr.substr(lastDollar + 1);
}

std::string encryptor(std::string encrKey, std::string normText, std::vector<unsigned char> hash) {
    std::string encrText;

    // Generate nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Encrypt
    std::vector<unsigned char> ciphertext(normText.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(),
        (const unsigned char*)normText.data(), normText.size(),
        nonce, hash.data());

    // Add nonce + ciphertext for output
    std::string resultStr((char*)nonce, sizeof nonce);
    resultStr += std::string((char*)ciphertext.data(), ciphertext.size());

    // Encode as base64 for display/storage
    char b64[2048];
    sodium_bin2base64(b64, sizeof b64,
        (const unsigned char*)resultStr.data(), resultStr.size(),
        sodium_base64_VARIANT_ORIGINAL);

    return std::string(b64);
}

std::string decryptor(std::string encrKey, std::string encrText, std::vector<unsigned char> hash) {

    // Decode base64
    std::vector<unsigned char> decoded(encrText.size());
    size_t decoded_len;
    if (sodium_base642bin(
            decoded.data(), decoded.size(),
            encrText.c_str(), encrText.size(),
            nullptr, &decoded_len, nullptr,
            sodium_base64_VARIANT_ORIGINAL) != 0) {
        std::cout << "Base64 decode failed\n";
        return "";
    }
    decoded.resize(decoded_len);

    // Extract nonce + cyphertext
    if (decoded.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        std::cout << "Ciphertext too short\n";
        return "";
    }
    const unsigned char* nonce = decoded.data();
    const unsigned char* ciphertext = decoded.data() + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = decoded.size() - crypto_secretbox_NONCEBYTES;

    // Decrypt
    std::vector<unsigned char> decrypted(ciphertext_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(
            decrypted.data(),
            ciphertext, ciphertext_len,
            nonce, hash.data()) != 0) {
        std::cout << "Decryption failed\n";
        return "";
    }

    return std::string((char*)decrypted.data(), decrypted.size());
}
