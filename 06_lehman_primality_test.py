# 6. Use the Lehmann algorithm to check whether the given number 
# P is prime or not?
# pow(5,7,77) = 47 build in power function epeansion -
#  modular_exponentiation

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

def is_prime_lehmann(P, num_iterations):
    # Base case: If P is less than 2, it's not prime
    if P < 2:
        return False
    
    for _ in range(num_iterations):
        # Randomly select A such that 2 <= A <= P - 1
        A = random.randint(2, P - 1)
        
        # Compute R = A^((P-1)/2) % P
        R = modular_exponentiation(A, (P - 1) // 2, P)
        
        # Print R to see the intermediate results
        # print(f"R: {R}")
        
        # Check if R is equal to 1 or -1 (mod P)
        if R != 1 and R != P - 1:
            return False  # P is composite
    
    return True  # P is probably prime

def main():
    P = int(input("Enter a number to check primality: "))
    num_iterations = 10  # Number of iterations for increased accuracy

    if is_prime_lehmann(P, num_iterations):
        print(f"{P} is probably prime.")
    else:
        print(f"{P} is composite.")

if __name__ == "__main__":
    main()

