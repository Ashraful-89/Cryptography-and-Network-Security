# 4.Find out corresponding double Transposition Cipher of the above plaintext. 
# Then perform the reverse operation to get original plaintext.

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
    plaintext = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLOGY UNIVERSITY OF RAISHAHI BANGLADESH"
    
    width = int(input("Please enter the width: "))

    print(f"Original plaintext: {plaintext}")

    # First Encryption
    encrypted_text = encrypt_transposition(plaintext, width)
    print(f"Encrypted text: {encrypted_text}")

    # Second Encryption (Double Transposition)
    double_encrypted_text = encrypt_transposition(encrypted_text, width)
    print(f"Double Encrypted text: {double_encrypted_text}")

    # First Decryption
    decrypted_text = decrypt_transposition(double_encrypted_text, width)
    print(f"Decrypted text: {decrypted_text}")
    
    # Second Decryption (Getting back to original text)
    double_decrypted_text = decrypt_transposition(decrypted_text, width)
    print(f"Double Decrypted text: {double_decrypted_text}")


if __name__ == "__main__":
    main()

