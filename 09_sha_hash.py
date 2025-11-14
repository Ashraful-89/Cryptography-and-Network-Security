import hashlib

def bytes_to_hex(hash_bytes):
    hex_string = ""
    for b in hash_bytes:
        hex_char = format(b, '02x')
        if len(hex_char) == 1:
            hex_string += '0'
        hex_string += hex_char
    return hex_string

def main():
    try:
        # Create a SHA-256 hash object
        sha256 = hashlib.sha256()

        # Update the hash object with the bytes of the input string
        input_string = "Hello World"
        sha256.update(input_string.encode('utf-8'))

        # Get the hash bytes
        hash_bytes = sha256.digest()

        # Print the raw byte hash (optional, for comparison)
        print(hash_bytes)

        # Convert the hash bytes to a hexadecimal string
        hash_hex = bytes_to_hex(hash_bytes)

        # Print the hexadecimal representation of the hash
        print(hash_hex)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
