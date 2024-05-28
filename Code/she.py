from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import bcrypt
import os

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdh_key_exchange(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = bcrypt.kdf(password=shared_key, salt=b'salt', desired_key_bytes=32, rounds=100)
    return derived_key

def ecdsa_sign(private_key, ciphertext):
    with open(ciphertext, 'rb') as file:
        ciphertext = file.read()
    signature = private_key.sign(ciphertext, ec.ECDSA(hashes.SHA256()))
    return signature

def ecdsa_verify(public_key, ciphertext_file, signature):
    with open(ciphertext_file, 'rb') as file:
        ciphertext = file.read()
    try:
        public_key.verify(signature, ciphertext, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        print("Alert: Intruder altered the digital signature")
        exit(1)

def generate_mac(key, ciphertext):
    mac = Poly1305.generate_tag(key, ciphertext)
    return mac

def verify_mac(key, ciphertext, provided_mac):
    computed_mac = Poly1305.generate_tag(key, ciphertext)
    return computed_mac == provided_mac

def generate_token():
    nonce = os.urandom(16)
    return nonce

def encryption(sender_shared_key, plaintext_file, encrypted_file):
    with open(plaintext_file, 'rb') as file:
        plaintext = file.read()

    nonce = generate_token()

    cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    mac = generate_mac(sender_shared_key, ciphertext)

    with open(encrypted_file, 'wb') as file:
        file.write(nonce + ciphertext + mac)

def decryption(receiver_shared_key, encrypted_file, decrypted_file):
    with open(encrypted_file, 'rb') as file:
        data = file.read()

    nonce = data[:16]
    ciphertext = data[16:-16]
    provided_mac = data[-16:]

    if verify_mac(sender_shared_key, ciphertext, provided_mac):
        cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(decrypted_file, 'wb') as file:
            file.write(plaintext)
    else:
        print("Alert: Intruder altered the MAC address")
        exit(1)

# Sender's keypair
sender_private_key, sender_public_key = generate_keypair()

# Receiver's keypair
receiver_private_key, receiver_public_key = generate_keypair()

# ECDH key exchange
sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key)
receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key)

# Files
plaintext_file = "Algorithm.docx"
encrypted_file = "encrypted_file.bin"
decrypted_file = "decrypted_file.docx"

# Ensuring both shared keys are the same for successful key exchange
if sender_shared_key == receiver_shared_key:
    # Encrypt the file
    encryption(sender_shared_key, plaintext_file, encrypted_file)

    # Digital signature
    signature = ecdsa_sign(sender_private_key, encrypted_file)

    # Verifying signature
    if ecdsa_verify(sender_public_key, encrypted_file, signature) is True:
        # Decrypt the file
        decryption(receiver_shared_key, encrypted_file, decrypted_file)
else:
    print("Alert: Intruder altered the key")
    exit(1)