def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2

    return result

def main():
    # Step 1: Agree on prime number and base (Known to both Alice and Bob)
    p = 23  # Prime number
    g = 5   # Base

    # Step 2: Generate private keys (known only to Alice and Bob)
    a = int(input("Alice's private key (a): "))
    b = int(input("Bob's private key (b): "))

    # Step 3: Calculate Public keys
    A = modular_exponentiation(g, a, p)  # Alice's public key
    B = modular_exponentiation(g, b, p)  # Bob's public key

    # Step 4: Exchange public keys (over the insecure channel)
    print("Alice's public key (A):", A)
    print("Bob's public key (B):", B)

    # Step 5: Calculate the secret key
    secret_key_alice = modular_exponentiation(B, a, p)  # Alice's secret key
    secret_key_bob = modular_exponentiation(A, b, p)    # Bob's secret key

    # Step 6: Both Alice and Bob have the same shared secret key
    print("Alice's secret key:", secret_key_alice)
    print("Bob's secret key:", secret_key_bob)

if __name__ == "__main__":
    main()
