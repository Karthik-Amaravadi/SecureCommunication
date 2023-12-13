from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


class SecureEncryption:
    def __init__(self):
        self.mode = ''
        self.pr_key = b''

    def create_key(self):
        key = b''
        if self.mode == '1':
            key = ChaCha20Poly1305.generate_key()
        elif self.mode == '2':
            key = AESGCM.generate_key(bit_length=128)
        elif self.mode == '3':
            key = AESOCB3.generate_key(bit_length=128)
        elif self.mode == '4':
            key = AESSIV.generate_key(bit_length=512)
        elif self.mode == '5':
            key = AESCCM.generate_key(bit_length=128)
        return key

    def convert_key(self,key):
        if self.mode == '1':
            self.pr_key = ChaCha20Poly1305(key)
        elif self.mode == '2':
            self.pr_key = AESGCM(key)
        elif self.mode == '3':
            self.pr_key = AESOCB3(key)
        elif self.mode == '4':
            self.pr_key = AESSIV(key)
        elif self.mode == '5':
            self.pr_key = AESCCM(key)
        return self.pr_key

    def encrypt_msg(self, msg, aad=b'CS645/745 Modern Cryptography',nonce = b'000000000000'):
        ct = b''
        if self.mode == '1' or self.mode=='2' or self.mode=='3' or self.mode=='5':
            ct = self.pr_key.encrypt(nonce, msg, aad)
        elif self.mode == '4':
            aad = [aad, nonce]
            ct = self.pr_key.encrypt(msg, aad)
        return ct

    def decrypt_msg(self, ch, ct, aad=b'CS645/745 Modern Cryptography', nonce=b'000000000000'):
        msg = b''
        if self.mode == '1' or self.mode=='2' or self.mode=='3' or self.mode=='5':
            msg = ch.decrypt(nonce, ct, aad)
        elif self.mode == '4':
            aad = [aad, nonce]
            msg = ch.decrypt(ct, aad)
        return msg

    def select_mode(self, mode):
        self.mode = mode
