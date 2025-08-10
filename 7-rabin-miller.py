# 7.	Use the Robin-Miller algorithm to check whether the given number P is prime or not?  

import random

def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    
    return result

def is_prime_miller_rabin(P, num_iterations):
    # Base case: if P is less than 2, it's not prime
    if P < 2:
        return False

    # Write P-1 as (2^r) * d
    r = 0
    d = P - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Perform the test num_iterations times
    for _ in range(num_iterations):
        # Randomly select a base a between 2 and P-2
        a = random.randint(2, P - 2)

        # Compute x = (a ^ d) mod P
        x = modular_exponentiation(a, d, P)

        # Check if x is equal to 1 or P-1 (mod P)
        if x != 1 and x != P - 1:
            # Perform r - 1 modular exponentiations
            for _ in range(r - 1):
                x = modular_exponentiation(x, 2, P)
                if x == P - 1:
                    break
            else:
                return False  # P is composite

    return True  # P is probably prime

def main():
    P = int(input("Enter a number to check primality: "))
    num_iterations = 10  # Number of iterations for increased accuracy

    if is_prime_miller_rabin(P, num_iterations):
        print(f"{P} is probably a prime number.")
    else:
        print(f"{P} is composite.")

if __name__ == "__main__":
    main()
