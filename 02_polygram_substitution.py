# 2.	Find out the Polygram Substitution Cipher of a given plaintext
# (Consider the block size of 3).
# Then perform the reverse operation to get original plaintext. 

def encrypt_polygram(plaintext, substitution_map):
    encrypted_text = ""

    # Loop through the plaintext in blocks of size 3
    for i in range(0, len(plaintext), 3):
        block = plaintext[i:i+3]

        # Check if the block exists in the substitution map
        if block in substitution_map: # key
            encrypted_text += substitution_map[block]
        else:
            encrypted_text += block  # If the block is not in the substitution map, keep it unchanged

    return encrypted_text


def decrypt_polygram(encrypted_text, substitution_map):
    decrypted_text = ""

    # Loop through the encrypted text in blocks of size 3
    for i in range(0, len(encrypted_text), 3):
        block = encrypted_text[i:i+3] #XJW

        # Reverse lookup in the substitution map to find the original plaintext block
        found = False
        for key, value in substitution_map.items():
            if value == block:
                decrypted_text += key
                found = True
                break

        # If the block is not found in the substitution map, keep it unchanged
        if not found:
            decrypted_text += block

    return decrypted_text


def main():
    # Original plaintext
    plaintext = input("Enter the plaintext: ")# HELLO WORLD
    print(f"Original Plaintext: {plaintext}")

    # Substitution map
    substitution_map = {
        "HEL": "PRI",
        "LO ": "MA ",
        "WOR": "MRD"
    }

    # Encryption
    encrypted_text = encrypt_polygram(plaintext, substitution_map)
    print(f"Encrypted Text: {encrypted_text}")

    # Decryption
    decrypted_text = decrypt_polygram(encrypted_text, substitution_map)
    print(f"Decrypted Text: {decrypted_text}")


if __name__ == "__main__":
    main()
