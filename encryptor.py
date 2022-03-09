"""
author: EtWnn, https://github.com/EtWnn

Main module of the repo: contains all the encryption / decryption logic
"""
import argparse
import base64
import unicodedata
from getpass import getpass
from pathlib import Path
import re
from typing import Union, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_derived_key(password: Union[str, bytes], salt: Union[int, bytes]) -> Fernet:
    """
    Generate a proper encryption key from a salt and a password

    :param password: user password
    :type password: Union[str, bytes]
    :param salt: user salt
    :type salt: Union[int, bytes]
    :return: fernet key
    :rtype: Fernet
    """
    if isinstance(salt, int):
        salt = salt.to_bytes((salt.bit_length() + 7) // 8, 'big')
    elif not isinstance(salt, bytes):
        raise ValueError(f"bytes or int types are expected for salt but got {salt} ({type(salt)})")

    if isinstance(password, str):
        password = bytes(password, encoding='utf8')
    elif not isinstance(password, bytes):
        raise ValueError(f"bytes or str types are expected for password but got {password} ({type(password)})")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)


def encrypt_write(content: Union[str, bytes], file_path: Path, key: Fernet):
    """
    Encrypt a content and write it to a file

    :param content: content to write in the file
    :type content: Union[str, bytes]
    :param file_path: path of the file
    :type file_path: Path
    :param key: key for encryption
    :type key: Fernel
    """
    if isinstance(content, str):
        content = bytes(content, encoding='utf-8')

    encrypted_content = key.encrypt(content)
    with open(file_path, 'wb') as file:
        file.write(encrypted_content)


def read_decrypt(file_path: Path, key: Fernet) -> bytes:
    """
    Decrypt the content of a file

    :param file_path: path of the file
    :type file_path: Path
    :param key: key for decryption
    :type key: Fernel
    :return: decrypted content
    :rtype: bytes
    """
    with open(file_path, 'rb') as file:
        encrypted_content = file.read()

    return key.decrypt(encrypted_content)


def ask_credentials() -> Tuple[str, int]:
    """
    Prompt the user for the password and the salt for encryption or decryption.
    Password will be set to lower case, accents will be converted and non-alphanumerical chars will be removed

    :return: the password and the salt
    :rtype: Tuple[str, int]
    """
    password = None
    while password is None:
        password = getpass("Please enter your password (input will be hidden):")
        try:
            password = ''.join(c for c in unicodedata.normalize('NFD', password) if unicodedata.category(c) != 'Mn')
            password = password.lower()
            password = re.sub(r'[^\w\d\s]+', ' ', password).strip()  # replace non-alphanumeric chars
        except Exception as e:
            print(e)
            print("An error occurred, please try again")
            password = None

    salt = None
    while salt is None:
        salt = getpass("Please enter your salt number (input will be hidden):")
        try:
            salt = int(salt)
        except ValueError:
            print("An error occurred while trying to convert your salt, please try again")
            salt = None

    return password, salt


def run_encryption(clear_file_path: Path, encrypted_file_path: Path):
    """
    Encryption process for a file

    :param clear_file_path: path to the file to be encrypted
    :type clear_file_path: Path
    :param encrypted_file_path: location where the encrypted file will be saved
    :type encrypted_file_path: Path
    """
    password, salt = ask_credentials()
    key = get_derived_key(password, salt)

    with open(clear_file_path) as file:
        clear_content = file.read()

    encrypt_write(clear_content, encrypted_file_path, key)
    print(f"Encrypted file successfully written to {encrypted_file_path}")


def run_decryption(encrypted_file_path: Path, clear_file_path: Path):
    """
    Decryption process for an encrypted file

    :param encrypted_file_path: path to the file to be decrypted
    :type encrypted_file_path: Path
    :param clear_file_path: location where the decrypted file will be saved
    :type clear_file_path: Path
    """
    password, salt = ask_credentials()
    key = get_derived_key(password, salt)

    try:
        clear_content = read_decrypt(encrypted_file_path, key).decode("utf-8")
    except InvalidToken:
        print("Decryption failed: Invalid token")
        return

    with open(clear_file_path, 'w') as file:
        file.write(clear_content)
    print(f"Decrypted file successfully written to {encrypted_file_path}")


def parse_args() -> argparse.Namespace:
    """
    Parse the arguments from a command line

    :return: name space with the parsed arguments
    :rtype: Namespace
    """
    parser = argparse.ArgumentParser(description="Script to decrypt or encrypt a file")

    parser.add_argument('command', metavar='cmd', type=str,
                        help="Action to be perform: 'encrypt' or 'decrypt'")
    parser.add_argument('file', type=str,
                        help="Path to the file to perform an action on")

    return parser.parse_args()


def main():

    args = parse_args()

    input_path = Path(args.file)

    if args.command == 'encrypt':
        output_path = input_path.parent / ('encrypted_' + input_path.name)
        run_encryption(input_path, output_path)
    elif args.command == 'decrypt':
        output_path = input_path.parent / ('decrypted_' + input_path.name)
        run_decryption(input_path, output_path)
    else:
        raise ValueError(f"Command must be one of {'encrypt', 'decrypt'}, got {args.cmd}")


if __name__ == '__main__':
    main()
