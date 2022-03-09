# FileEncryptor

This repo is a simple helper to encrypt / decrypt files.
It entirely relies on the [cryptography](https://pypi.org/project/cryptography/) package: don't hesitate to read
how they addresse security issues in this [article](https://cryptography.io/en/latest/security/)


### Installation

Create a virtual environment with python 3.9, for example with conda:

```
conda create -n encr_env python=3.9
```

Install the package in your virtual environment:
```
conda activate encr_env
pip install git+https://github.com/EtWnn/FileEncryptor
```


### File Encryption

To encrypt a file, execute the command:

```
conda activate encr_env
file_encryptor encrypt <path/to/file>
```

The encrypted file will be written at `<path/to/encrypted_file`


### File Decryption

To decrypt a file execute the command:

```
conda activate encr_env
file_encryptor decrypt <path/to/file>
```

The decrypted file will be written at `<path/to/decrypted_file`


### Credentials

For every encryption or decryption, you will be prompted a password and a salt.

The password is non-case sensitive, accents will be converted and punctuation will be removed.
The salt is a number used in encryption key generation process.

To achieve a successful decryption, both password and salt must be identical to the ones used
when encrypting a file.