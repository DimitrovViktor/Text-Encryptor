# <div align = "center"> TextEncryptor </div>

<div align="center">

[![C++](https://img.shields.io/badge/C++-%2300599C.svg?logo=c%2B%2B&logoColor=white)](#)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

C++ application for encrypting and decrypting text using Argon2 password hashing and libsodium symmetric encryption, with a Qt6 GUI.

</div>

---

![App](https://github.com/user-attachments/assets/3014c896-83e1-4084-930e-df3f3db0702d)

---

## Features

Password based encryption using Argon2id key derivation and libsodium's secretbox. Encrypted output uses a multi alphabet encoding where each byte maps to a character. The character mapping is derived from the password hash, making the encoding itself password dependent and adding an extra layer of obfuscation.


## How it works

The user sets a password which is hashed with Argon2id to derive a key. The hash also seeds a deterministic shuffle of a character pool across six alphabets, producing a unique lookup table. 

Text is encrypted with libsodium secretbox, then each byte of the result is mapped through the shuffled table. Decryption reverses both layers. Without the correct password, neither the character mapping nor the ciphertext can be reversed.

## Qt GUI version

![UI](https://github.com/user-attachments/assets/97c724fd-e968-4952-9fa5-0108aa8f8087)

The Qt6 desktop application is in the `Qt/Encryptor/` directory. It provides password setting with lock/change functionality, side by side text areas for unencrypted and encrypted text, status bar feedback, and a fully resizable layout.


## Libraries used

- **Argon2** — password hashing (Argon2id variant)
- **libsodium** — symmetric encryption (secretbox), nonce generation, base64 utilities

## CLI version

The original CLI version is in `TextEncryptor.cpp` at the project root. It uses the same Argon2 + libsodium encryption but with standard base64 output and command-line input/output.
