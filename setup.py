import os
from setuptools import setup

from src import __version__

this_directory = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

with open("requirements.txt") as file:
    requirements_content = file.read()
requirements = requirements_content.split('\n')

setup(
    name='file_encryptor',
    version=__version__,
    packages=['file_encryptor'],
    install_requires=requirements,
    entry_points={
        'console_scripts': ['file_encryptor=file_encryptor.encryptor:main']
    },
    url='https://github.com/EtWnn/FileEncryptor',
    author='EtWnn',
    author_email='EtWnn0x@gmail.com',
    license='MIT',
    description='Simple helper to encrpyt / decrypt sensitive files',
    long_description=long_description,
    keywords='encryption decryption sensitive data file'
)
