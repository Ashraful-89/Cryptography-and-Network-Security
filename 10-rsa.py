def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2

    return result

def rsa_key_generation(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose a public exponent e such that 1 < e < phi and gcd(e, phi) = 1
    e = 17
    while e >= phi or gcd(e, phi) != 1:
        e += 1

    # Calculate the private exponent d as the modular inverse of e modulo phi
    d = 1
    while (d * e) % phi != 1:
        d += 1

    return (e, n), (d, n)

def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    return modular_exponentiation(plaintext, e, n)

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    return modular_exponentiation(ciphertext, d, n)

def main():
    # Step 1: Key Generation
    p = 61
    q = 53
    public_key, private_key = rsa_key_generation(p, q)

    # Step 2: Encryption
    plaintext = 123
    ciphertext = rsa_encrypt(plaintext, public_key)

    # Step 3: Decryption
    decrypted_text = rsa_decrypt(ciphertext, private_key)

    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted Text: {decrypted_text}")

if __name__ == "__main__":
    main()
