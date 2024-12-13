class RSAEncryption:
    def __init__(self, public_key):
        self.n, self.e = public_key

    def encrypt(self, message):
        if isinstance(message, str):
            message = int.from_bytes(message.encode('utf-8'), byteorder='big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, byteorder='big')
        return pow(message, self.e, self.n)


class RSADecryption:
    def __init__(self, private_key):
        self.p = private_key['p']
        self.q = private_key['q']
        self.dp = private_key['dp']
        self.dq = private_key['dq']
        self.qinv = private_key['qinv']

    def decrypt(self, ciphertext):
        m1 = pow(ciphertext, self.dp, self.p)
        m2 = pow(ciphertext, self.dq, self.q)
        h = (self.qinv * (m1 - m2)) % self.p
        decrypted_message = (m2 + h * self.q) % (self.p * self.q)
        try:
            return decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
        except UnicodeDecodeError:
            return decrypted_message