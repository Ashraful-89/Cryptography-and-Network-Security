def repeat_key(key, length):
    return (key * (length // len(key) + 1))[:length]

def shift_char(c, k, mode):
    if c.isalpha() and k.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        shift_value = ord(k.upper() if c.isupper() else k.lower()) - base
        shifted_index = (ord(c) - base + mode * shift_value) % 26
        return chr(shifted_index + base)
    else:
        return c  # Non-alphabetic characters are returned as-is

def encrypt(plaintext, key):
    key = repeat_key(key, len(plaintext))
    ciphertext = ''.join(shift_char(p, k, 1) if p.isalpha() else p for p, k in zip(plaintext, key))
    return ciphertext

def decrypt(ciphertext, key):
    key = repeat_key(key, len(ciphertext))
    plaintext = ''.join(shift_char(c, k, -1) if c.isalpha() else c for c, k in zip(ciphertext, key))
    return plaintext

def main():
    plaintext = "BANGLADESH"
    with open('codes-o/5-key.txt', 'r') as file:
        key = file.read().strip()

    ciphertext = encrypt(plaintext, key)
    print(f"Ciphertext: {ciphertext}")

    decrypted_text = decrypt(ciphertext, key)
    print(f"Decrypted Text: {decrypted_text}")

if __name__ == "__main__":
    main()




# old
# import string

# def repeat_key(key, length):
#     return (key * (length // len(key) + 1))[:length]

# def shift_char(c, k, mode):
#     if c.isalpha() and k.isalpha():
#         alphabet = string.ascii_uppercase if c.isupper() else string.ascii_lowercase
#         shifted_index = (alphabet.index(c) + mode * alphabet.index(k.upper() if c.isupper() else k.lower())) % 26
#         return alphabet[shifted_index]
#     else:
#         return c  # Return the character unchanged if it's not alphabetic

# def encrypt(plaintext, key):
#     key = repeat_key(key, len(plaintext))
#     ciphertext = [shift_char(p, k, 1) if p.isalpha() else p for p, k in zip(plaintext, key)]
#     return ''.join(ciphertext)

# def decrypt(ciphertext, key):
#     key = repeat_key(key, len(ciphertext))
#     plaintext = [shift_char(c, k, -1) if c.isalpha() else c for c, k in zip(ciphertext, key)]
#     return ''.join(plaintext)

# def main():
#     plaintext = "BANGLADESH"
#     with open('codes-o/5-key.txt', 'r') as file:
#         key = file.read().strip()

#     ciphertext = encrypt(plaintext, key)
#     print(f"Ciphertext: {ciphertext}")

#     decrypted_text = decrypt(ciphertext, key)
#     print(f"Decrypted Text: {decrypted_text}")

# if __name__ == "__main__":
#     main()
