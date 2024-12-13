import random
from sympy import isprime, mod_inverse

def generate_large_prime(bits):
    """Generates a large prime number of approximately 'bits' size."""
    while True:
        # Generate a random odd number of the specified bit length
        candidate = random.getrandbits(bits) | 1
        # Test for primality
        if isprime(candidate):
            return candidate

def choose_public_exponent(phi):
    """Chooses a public exponent 'e' such that gcd(e, phi) = 1."""
    # Commonly used value for e
    e = 65537
    if phi % e == 0:  # Ensure e is coprime with phi
        raise ValueError("Public exponent e is not coprime with phi.")
    return e

class KeyGenerator:
    def __init__(self, key_size=2048):
        """Initializes the KeyGenerator with a given key size."""
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """Generates RSA keys optimized for CRT."""
        # Step 1: Generate two large primes, p and q
        p = generate_large_prime(self.key_size // 2)
        q = generate_large_prime(self.key_size // 2)

        # Ensure p and q are distinct
        while p == q:
            q = generate_large_prime(self.key_size // 2)

        # Step 2: Compute n and phi(n)
        n = p * q
        phi = (p - 1) * (q - 1)

        # Step 3: Choose a public exponent e
        e = choose_public_exponent(phi)

        # Step 4: Compute the private exponent d
        d = mod_inverse(e, phi)

        # Step 5: Compute CRT-specific components
        dp = d % (p - 1)  # d mod (p-1)
        dq = d % (q - 1)  # d mod (q-1)
        qinv = mod_inverse(q, p)  # q^(-1) mod p

        # Step 6: Store the keys
        self.public_key = (n, e)
        self.private_key = {
            "p": p,
            "q": q,
            "d": d,
            "dp": dp,
            "dq": dq,
            "qinv": qinv,
        }

    def get_keys(self):
        """Returns the generated public and private keys."""
        if not self.public_key or not self.private_key:
            raise ValueError("Keys have not been generated yet.")
        return self.public_key, self.private_key



    
