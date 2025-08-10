# 8.	Write a program to implement MD5 one way hash function.

import hashlib

def get_md5(input_string):
    # Create an MD5 hash object
    md5_hash = hashlib.md5()

    # Update the hash object with the bytes of the input string
    md5_hash.update(input_string.encode('utf-8'))

    # Get the hexadecimal representation of the digest
    hashtext = md5_hash.hexdigest()

    # Ensure the hash is 32 characters long by padding with zeros if necessary
    while len(hashtext) < 32:
        hashtext = "0" + hashtext

    return hashtext

def main():
    s = "Hello World"
    print("Original String:", s)
    print("MD5 hash of the string:", get_md5(s))

if __name__ == "__main__":
    main()
