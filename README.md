# Text Encryptor

A C++ text encryption and decryption tool using hashed passwords as encryption keys

## Features

1. Encryption keys

User picks a password, password gets turned to hash, hash is used as encryption key.

2. Text Encryption (in progress)

Text(unencrypted) and password hash are taken, text is encrypted based on password.

3. Text Decryption (in progress)

Text(encrypted) and password hash are taken, text is decrypted based on password.

## UI (in progress)

![UI](https://github.com/user-attachments/assets/275e471e-0ddd-49ac-a43b-9a115bc69fd5)

- Password selection
- Encryption
- Decryption

## Libraries and Frameworks used:

- Argon (hashing)
- Libsodium (encryption)
- Qt (UI)

## TO-DO:

- Different alphabets for encrypted text mixed into one message with salt (e.g. Cyrillic, Arabic)
- salt at the start and end of encrypted text baseed on password
