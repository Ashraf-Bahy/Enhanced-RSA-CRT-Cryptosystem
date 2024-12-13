from sympy import randprime, mod_inverse

class TraditionalRSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        p = randprime(2 ** (self.key_size // 2 - 1), 2 ** (self.key_size // 2))
        q = randprime(2 ** (self.key_size // 2 - 1), 2 ** (self.key_size // 2))
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = mod_inverse(e, phi)
        self.public_key = (n, e)
        self.private_key = (n, d)

    def encrypt(self, message):
        n, e = self.public_key
        if isinstance(message, str):
            message = int.from_bytes(message.encode('utf-8'), byteorder='big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, byteorder='big')
        return pow(message, e, n)

    def decrypt(self, ciphertext):
        n, d = self.private_key
        decrypted_message = pow(ciphertext, d, n)
        try:
            return decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
        except UnicodeDecodeError:
            return decrypted_message