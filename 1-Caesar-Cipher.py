# 1.	Suppose you are given a line of text as a plaintext, find out the corresponding Caesar Cipher 
# (i.e. character three to the right modulo 26). Then perform the reverse operation to get original 
# plaintext.

def caesar_cipher_encryption(plain_text, shift_value):
    encrypted_text = ""
 
    for c in plain_text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            encrypted = chr(((ord(c) - base + shift_value) % 26) + base)
            encrypted_text += encrypted
        else:
            encrypted_text += c

    return encrypted_text


def caesar_cipher_decryption(encrypted_text, shift_value):
    decrypt_key = (26 - shift_value) % 26
    print('Decrypt key:',decrypt_key)
    return caesar_cipher_encryption(encrypted_text, decrypt_key)


def main():
    # Taking Original text and the shift value from user
    s = input("Please enter your text: ")
    shift_value = int(input("Please enter the shift value: "))

    print(f"Original text: {s}")

    # Calling encryption function to encrypt the original text
    encrypted_text = caesar_cipher_encryption(s, shift_value)
    print(f"Encrypted text: {encrypted_text}")

    # Calling decryption function to decrypt the encrypted text
    decrypted_text = caesar_cipher_decryption(encrypted_text, shift_value)
    print(f"Decrypted text: {decrypted_text}")


if __name__ == "__main__":
    main()
