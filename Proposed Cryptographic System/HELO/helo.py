import asyncio
import os
import concurrent.futures
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

def chunk_size():
    chunk_size = int(input("Enter chunk size: "))
    return chunk_size

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdh_key_exchange(private_key, public_key, salt):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

def ecdsa_sign(private_key, data):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def ecdsa_verify(public_key, data, signature):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        print("Alert: Intruder altered the digital signature")
        exit(1)

def generate_mac(key, data):
    mac = Poly1305.generate_tag(key, data)
    return mac

def verify_mac(key, data, provided_mac):
    computed_mac = Poly1305.generate_tag(key, data)
    return computed_mac == provided_mac

def generate_token():
    nonce = os.urandom(16)
    return nonce

def process_chunked_file_for_encryption(plaintext_file, encrypted_file, sender_shared_key, sender_private_key):
    chunked_data = chunk_size()  # Get chunk size from user input

    nonce = generate_token()
    cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None)
    encryptor = cipher.encryptor()

    with open(plaintext_file, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
        outfile.write(nonce)
        while chunk := infile.read(chunked_data):
            ciphertext = encryptor.update(chunk)
            outfile.write(ciphertext)
        outfile.write(encryptor.finalize())

    with open(encrypted_file, 'rb') as infile:
        ciphertext = infile.read()[16:]  # Skip the nonce
        mac = generate_mac(sender_shared_key, ciphertext)

    with open(encrypted_file, 'ab') as outfile:
        outfile.write(mac)

    # Signing the encrypted file
    with open(encrypted_file, 'rb') as file:
        ciphertext = file.read()

    signature = ecdsa_sign(sender_private_key, ciphertext)

    with open(encrypted_file + ".sig", 'wb') as sig_file:
        sig_file.write(signature)

def process_chunked_file_for_decryption(encrypted_file, decrypted_file, receiver_shared_key, sender_public_key):
    # Verifying the signature
    with open(encrypted_file, 'rb') as file:
        ciphertext = file.read()

    with open(encrypted_file + ".sig", 'rb') as sig_file:
        signature = sig_file.read()

    if ecdsa_verify(sender_public_key, ciphertext, signature):
        with open(encrypted_file, 'rb') as file:
            nonce = file.read(16)
            data = file.read()

        ciphertext = data[:-16]
        provided_mac = data[-16:]

        if verify_mac(receiver_shared_key, ciphertext, provided_mac):
            cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None)
            decryptor = cipher.decryptor()

            with open(decrypted_file, 'wb') as outfile:
                outfile.write(decryptor.update(ciphertext))
                outfile.write(decryptor.finalize())
        else:
            print("Alert: Intruder altered the MAC address")
            exit(1)
    else:
        print("Alert: Signature verification failed")
        exit(1)

def multithreading_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for filename in os.listdir(folder_path):
            plaintext_file = os.path.join(folder_path, filename)
            encrypted_file = os.path.join(encrypted_folder_path, filename + ".enc")
            futures.append(executor.submit(process_chunked_file_for_encryption, plaintext_file, encrypted_file, sender_shared_key, sender_private_key))
        concurrent.futures.wait(futures)

def multithreading_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for filename in os.listdir(encrypted_folder_path):
            if filename.endswith(".enc"):
                encrypted_file = os.path.join(encrypted_folder_path, filename)
                decrypted_file = os.path.join(decrypted_folder_path, filename[:-4])
                futures.append(executor.submit(process_chunked_file_for_decryption, encrypted_file, decrypted_file, receiver_shared_key, sender_public_key))
        concurrent.futures.wait(futures)

def process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
    if not os.path.exists(encrypted_folder_path):
        os.makedirs(encrypted_folder_path)

    multithreading_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)

def process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
    if not os.path.exists(decrypted_folder_path):
        os.makedirs(decrypted_folder_path)

    multithreading_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)

async def main():
    print("NOTE: Chunk size will be initialized as bytes by default.\nHowever, you need to convert bytes it into another unit.\n")
    
    sender_private_key, sender_public_key = generate_keypair()
    receiver_private_key, receiver_public_key = generate_keypair()

    salt = os.urandom(16)

    sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key, salt)
    receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key, salt)

    if sender_shared_key == receiver_shared_key:
        folder_path = "original file"
        encrypted_folder_path = "encrypted_file"
        decrypted_folder_path = "decrypted_file"

        process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)
        process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)
    else:
        print("Alert: Intruder altered the key")
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())