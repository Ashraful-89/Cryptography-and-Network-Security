# 3.	Consider the plaintext 
# “DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLOGY,
#  find out the corresponding Transposition Cipher 
#  (Take width as input). 
#  Then perform the reverse operation to get original plaintext.

import math

def encrypt_transposition(plaintext, width):
    encrypted_text = ""
    height = math.ceil(len(plaintext) / width)
    total_chars = height * width

    # Padding the plaintext with spaces if necessary
    padded_text = plaintext
    if len(padded_text) < total_chars:
        padding = total_chars - len(padded_text)
        padded_text += ' ' * padding
    
    # Performing encryption
    for col in range(width):
        for row in range(height):
            index = col + (row * width)
            encrypted_text += padded_text[index]

    return encrypted_text


def decrypt_transposition(encrypted_text, width):
    decrypted_text = ""
    height = math.ceil(len(encrypted_text) / width)

    for row in range(height):
        for col in range(width):
            index = col * height + row
            decrypted_text += encrypted_text[index]

    return decrypted_text


def main():
    # Example plaintext
    plaintext = "PREMA"
    
    width = int(input("Please enter the width: "))
 
    print(f"Original plaintext: {plaintext}")

    # Encryption
    encrypted_text = encrypt_transposition(plaintext, width)
    print(f"Encrypted text: {encrypted_text}")

    # Decryption
    decrypted_text = decrypt_transposition(encrypted_text, width)
    print(f"Decrypted text: {decrypted_text}")


if __name__ == "__main__":
    main()
