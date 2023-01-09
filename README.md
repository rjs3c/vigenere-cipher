# Vigenère Cipher

## Contents
1. [Description](#description)
2. [Installation](#installation)
3. [Usage](#Usage)

## Description
A C-based Implementation of the Vigenère Cipher.

## Installation
* **Compile and Execute on GNU/Linux using GCC**
```bash
$ gcc vigenere.c -o vigenere
$ chmod +x vigenere
$ ./vigenere
```

* **Compile and Execute on Windows NT using the VS Developer Command Prompt**
```cmd
$ cl vigenere.c
$ .\vigenere.exe
```
## Usage
```
usage: ./vigenere [-h] "message" [-m MODE] [-k "KEY"]

positional arguments:
      message  specifies the message to encrypt/decrypt (A-Z, a-z).
      -m       encrypt/decrypt the subsequent message.
               (0 = encrypt, 1 = decrypt, 0 = default)
      -k       specifies the keyword to use (variable length, ASCII-only).

optional arguments:
      -h       displays help message and usage information.
```
