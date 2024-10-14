# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
# from cryptography.hazmat.primitives.poly1305 import Poly1305
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.exceptions import InvalidSignature
# import concurrent.futures
# import bcrypt
# import os
# import time
# import psutil
#
# chunk_size = 64 * 1024  # 64KB
#
# def generate_keypair():
#     private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
#     public_key = private_key.public_key()
#     return private_key, public_key
#
# def ecdh_key_exchange(private_key, public_key):
#     shared_key = private_key.exchange(ec.ECDH(), public_key)
#     derived_key = bcrypt.kdf(password=shared_key, salt=b'salt', desired_key_bytes=32, rounds=50)
#     return derived_key
#
# def ecdsa_sign(private_key, data):
#     signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
#     return signature
#
# def ecdsa_verify(public_key, data, signature):
#     try:
#         public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
#         return True
#     except InvalidSignature:
#         print("Alert: Intruder altered the digital signature")
#         exit(1)
#
# def generate_mac(key, data):
#     mac = Poly1305.generate_tag(key, data)
#     return mac
#
# def verify_mac(key, data, provided_mac):
#     computed_mac = Poly1305.generate_tag(key, data)
#     return computed_mac == provided_mac
#
# def generate_token():
#     nonce = os.urandom(16)
#     return nonce
#
# def encryption(sender_shared_key, plaintext_file, encrypted_file):
#     nonce = generate_token()
#     cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None, backend=default_backend())
#     encryptor = cipher.encryptor()
#
#     with open(plaintext_file, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
#         outfile.write(nonce)
#         while chunk := infile.read(chunk_size):
#             ciphertext = encryptor.update(chunk)
#             outfile.write(ciphertext)
#         outfile.write(encryptor.finalize())
#
#     with open(encrypted_file, 'rb') as infile:
#         infile.seek(16)  # Skip the nonce
#         mac = Poly1305.generate_tag(sender_shared_key, infile.read())
#
#     with open(encrypted_file, 'ab') as outfile:
#         outfile.write(mac)
#
# def decryption(receiver_shared_key, encrypted_file, decrypted_file):
#     with open(encrypted_file, 'rb') as infile:
#         nonce = infile.read(16)
#         data = infile.read()
#
#     ciphertext = data[:-16]
#     provided_mac = data[-16:]
#
#     if verify_mac(receiver_shared_key, ciphertext, provided_mac):
#         cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None, backend=default_backend())
#         decryptor = cipher.decryptor()
#
#         with open(decrypted_file, 'wb') as outfile:
#             outfile.write(decryptor.update(ciphertext))
#             outfile.write(decryptor.finalize())
#     else:
#         print("Alert: Intruder altered the MAC address")
#         exit(1)
#
# def process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
#     if not os.path.exists(encrypted_folder_path):
#         os.makedirs(encrypted_folder_path)
#
#     def process_file(filename):
#         plaintext_file = os.path.join(folder_path, filename)
#         encrypted_file = os.path.join(encrypted_folder_path, filename + ".enc")
#
#         # Encrypt the file
#         encryption(sender_shared_key, plaintext_file, encrypted_file)
#
#         # Sign the encrypted file in chunks to avoid large memory usage
#         hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
#         with open(encrypted_file, 'rb') as file:
#             while chunk := file.read(chunk_size):
#                 hasher.update(chunk)
#         signature = sender_private_key.sign(hasher.finalize(), ec.ECDSA(hashes.SHA256()))
#
#         # Save the signature
#         with open(encrypted_file + ".sig", 'wb') as sig_file:
#             sig_file.write(signature)
#
#     with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
#         executor.map(process_file, os.listdir(folder_path))
#
# def process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
#     if not os.path.exists(decrypted_folder_path):
#         os.makedirs(decrypted_folder_path)
#
#     def process_file(filename):
#         if filename.endswith(".enc"):
#             encrypted_file = os.path.join(encrypted_folder_path, filename)
#             decrypted_file = os.path.join(decrypted_folder_path, filename[:-4])
#
#             # Verify and decrypt the file in chunks
#             hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
#             with open(encrypted_file, 'rb') as file:
#                 while chunk := file.read(chunk_size):
#                     hasher.update(chunk)
#             provided_signature = hasher.finalize()
#
#             with open(encrypted_file + ".sig", 'rb') as sig_file:
#                 signature = sig_file.read()
#
#             if ecdsa_verify(sender_public_key, provided_signature, signature):
#                 decryption(receiver_shared_key, encrypted_file, decrypted_file)
#
#     with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
#         executor.map(process_file, os.listdir(encrypted_folder_path))
#
# # Measure power consumption and RAM usage
# def measure_performance():
#     process = psutil.Process(os.getpid())
#     cpu_times = process.cpu_times()
#     memory_info = process.memory_info()
#
#     cpu_usage = cpu_times.user
#     memory_usage = memory_info.rss / (1024 * 1024)
#
#     return cpu_usage, memory_usage
#
# def main():
#     print("..........HELO Hardware Analysis..........")
#
#     # Measure performance before the process
#     cpu_before, memory_before = measure_performance()
#
#     start = time.time()
#
#     # Sender's keypair
#     sender_private_key, sender_public_key = generate_keypair()
#
#     # Receiver's keypair
#     receiver_private_key, receiver_public_key = generate_keypair()
#
#     # ECDH key exchange
#     sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key)
#     receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key)
#
#     # Ensure both shared keys are the same for successful key exchange
#     if sender_shared_key == receiver_shared_key:
#         folder_path = "original file"
#         encrypted_folder_path = "encrypted file"
#         decrypted_folder_path = "decrypted file"
#
#         # Encrypt the folder
#         process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)
#
#         # Decrypt the folder
#         process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)
#     else:
#         print("Alert: Intruder altered the key")
#         exit(1)
#
#     end = time.time()
#     total_time = end - start
#     print("Runtime of AES: {:.2f} s".format(total_time))
#
#     # Measure performance after the process
#     cpu_after, memory_after = measure_performance()
#
#     cpu_result = cpu_after - cpu_before
#     memory_result = memory_after - memory_before
#
#     print("CPU time: {:.2f} seconds".format(cpu_result))
#     print("RAM usage: {:.2f} MB".format(memory_result))
#
# if __name__ == "__main__":
#     main()



# import asyncio
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
# from cryptography.hazmat.primitives.poly1305 import Poly1305
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.exceptions import InvalidSignature
# import bcrypt
# import time
# import os
# import psutil
#
# chunk_size = 64 * 1024  # 64KB
#
# def generate_keypair():
#     private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
#     public_key = private_key.public_key()
#     return private_key, public_key
#
# def ecdh_key_exchange(private_key, public_key):
#     shared_key = private_key.exchange(ec.ECDH(), public_key)
#     derived_key = bcrypt.kdf(password=shared_key, salt=b'salt', desired_key_bytes=32, rounds=50)
#     return derived_key
#
# def ecdsa_sign(private_key, data):
#     signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
#     return signature
#
# def ecdsa_verify(public_key, data, signature):
#     try:
#         public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
#         return True
#     except InvalidSignature:
#         print("Alert: Intruder altered the digital signature")
#         exit(1)
#
# def generate_mac(key, data):
#     mac = Poly1305.generate_tag(key, data)
#     return mac
#
# def verify_mac(key, data, provided_mac):
#     computed_mac = Poly1305.generate_tag(key, data)
#     return computed_mac == provided_mac
#
# def generate_token():
#     nonce = os.urandom(16)
#     return nonce
#
# async def encryption(sender_shared_key, plaintext_file, encrypted_file):
#     nonce = generate_token()
#     cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None, backend=default_backend())
#     encryptor = cipher.encryptor()
#
#     with open(plaintext_file, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
#         outfile.write(nonce)
#         while chunk := infile.read(chunk_size):
#             ciphertext = encryptor.update(chunk)
#             outfile.write(ciphertext)
#         outfile.write(encryptor.finalize())
#
#     with open(encrypted_file, 'rb') as infile:
#         ciphertext = infile.read()[16:]  # Skip the nonce
#         mac = generate_mac(sender_shared_key, ciphertext)
#
#     with open(encrypted_file, 'ab') as outfile:
#         outfile.write(mac)
#
# async def decryption(receiver_shared_key, encrypted_file, decrypted_file):
#     with open(encrypted_file, 'rb') as infile:
#         nonce = infile.read(16)
#         data = infile.read()
#
#     ciphertext = data[:-16]
#     provided_mac = data[-16:]
#
#     if verify_mac(receiver_shared_key, ciphertext, provided_mac):
#         cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None, backend=default_backend())
#         decryptor = cipher.decryptor()
#
#         with open(decrypted_file, 'wb') as outfile:
#             outfile.write(decryptor.update(ciphertext))
#             outfile.write(decryptor.finalize())
#     else:
#         print("Alert: Intruder altered the MAC address")
#         exit(1)
#
# async def process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
#     if not os.path.exists(encrypted_folder_path):
#         os.makedirs(encrypted_folder_path)
#
#     for filename in os.listdir(folder_path):
#         plaintext_file = os.path.join(folder_path, filename)
#         encrypted_file = os.path.join(encrypted_folder_path, filename + ".enc")
#
#         # Encrypt the file
#         await encryption(sender_shared_key, plaintext_file, encrypted_file)
#
#         # Read the encrypted file to sign it
#         with open(encrypted_file, 'rb') as file:
#             ciphertext = file.read()
#
#         # Digital signature
#         signature = ecdsa_sign(sender_private_key, ciphertext)
#
#         # Save the signature
#         with open(encrypted_file + ".sig", 'wb') as sig_file:
#             sig_file.write(signature)
#
# async def process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
#     if not os.path.exists(decrypted_folder_path):
#         os.makedirs(decrypted_folder_path)
#
#     for filename in os.listdir(encrypted_folder_path):
#         if filename.endswith(".enc"):
#             encrypted_file = os.path.join(encrypted_folder_path, filename)
#             decrypted_file = os.path.join(decrypted_folder_path, filename[:-4])
#
#             # Read the encrypted file to verify it
#             with open(encrypted_file, 'rb') as file:
#                 ciphertext = file.read()
#
#             # Read the signature file
#             with open(encrypted_file + ".sig", 'rb') as sig_file:
#                 signature = sig_file.read()
#
#             # Verifying signature
#             if ecdsa_verify(sender_public_key, ciphertext, signature):
#                 # Decrypt the file
#                 await decryption(receiver_shared_key, encrypted_file, decrypted_file)
#
#
# # Measure power consumption and RAM usage
# def measure_performance():
#     process = psutil.Process(os.getpid())
#     cpu_times = process.cpu_times()
#     memory_info = process.memory_info()
#
#     cpu_usage = cpu_times.user
#     memory_usage = memory_info.rss / (1024 * 1024)
#
#     return cpu_usage, memory_usage
#
#
# async def main():
#     print("..........HELO Hardware Analysis..........")
#
#     # Measure performance before the process
#     cpu_before, memory_before = measure_performance()
#
#     start = time.time()
#
#     # Sender's keypair
#     sender_private_key, sender_public_key = generate_keypair()
#
#     # Receiver's keypair
#     receiver_private_key, receiver_public_key = generate_keypair()
#
#     # ECDH key exchange
#     sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key)
#     receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key)
#
#     # Ensure both shared keys are the same for successful key exchange
#     if sender_shared_key == receiver_shared_key:
#         folder_path = "(95 MB) Cityscapes Image Pairs"
#         encrypted_folder_path = "encrypted file"
#         decrypted_folder_path = "decrypted file"
#
#         # Encrypt the folder
#         await process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)
#
#         # Decrypt the folder
#         await process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)
#     else:
#         print("Alert: Intruder altered the key")
#         exit(1)
#
#     end = time.time()
#     total_time = end - start
#     print("Runtime: {:.2f} s".format(total_time))
#
#     # Measure performance after the process
#     cpu_after, memory_after = measure_performance()
#
#     cpu_result = cpu_after - cpu_before
#     memory_result = memory_after - memory_before
#
#     print("CPU time: {:.2f} seconds".format(cpu_result))
#     print("RAM usage: {:.2f} MB".format(memory_result))
#
# if __name__ == "__main__":
#     asyncio.run(main())





# import asyncio
# import os
# import time
# import psutil
# import concurrent.futures
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
# from cryptography.hazmat.primitives.poly1305 import Poly1305
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.exceptions import InvalidSignature
# import bcrypt
#
# chunk_size = 256 * 1024  # 256KB
#
# def generate_keypair():
#     private_key = ec.generate_private_key(ec.SECP256R1())
#     public_key = private_key.public_key()
#     return private_key, public_key
#
# def ecdh_key_exchange(private_key, public_key):
#     shared_key = private_key.exchange(ec.ECDH(), public_key)
#     derived_key = bcrypt.kdf(password=shared_key, salt=b'salt', desired_key_bytes=32, rounds=50)
#     return derived_key
#
# def ecdsa_sign(private_key, data):
#     signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
#     return signature
#
# def ecdsa_verify(public_key, data, signature):
#     try:
#         public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
#         return True
#     except InvalidSignature:
#         print("Alert: Intruder altered the digital signature")
#         exit(1)
#
# def generate_mac(key, data):
#     mac = Poly1305.generate_tag(key, data)
#     return mac
#
# def verify_mac(key, data, provided_mac):
#     computed_mac = Poly1305.generate_tag(key, data)
#     return computed_mac == provided_mac
#
# def generate_token():
#     nonce = os.urandom(16)
#     return nonce
#
# def encrypt_file(sender_shared_key, plaintext_file, encrypted_file):
#     nonce = generate_token()
#     cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None)
#     encryptor = cipher.encryptor()
#
#     with open(plaintext_file, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
#         outfile.write(nonce)
#         while chunk := infile.read(chunk_size):
#             ciphertext = encryptor.update(chunk)
#             outfile.write(ciphertext)
#         outfile.write(encryptor.finalize())
#
#     with open(encrypted_file, 'rb') as infile:
#         ciphertext = infile.read()[16:]  # Skip the nonce
#         mac = generate_mac(sender_shared_key, ciphertext)
#
#     with open(encrypted_file, 'ab') as outfile:
#         outfile.write(mac)
#
# def decrypt_file(receiver_shared_key, encrypted_file, decrypted_file):
#     with open(encrypted_file, 'rb') as infile:
#         nonce = infile.read(16)
#         data = infile.read()
#
#     ciphertext = data[:-16]
#     provided_mac = data[-16:]
#
#     if verify_mac(receiver_shared_key, ciphertext, provided_mac):
#         cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None)
#         decryptor = cipher.decryptor()
#
#         with open(decrypted_file, 'wb') as outfile:
#             outfile.write(decryptor.update(ciphertext))
#             outfile.write(decryptor.finalize())
#     else:
#         print("Alert: Intruder altered the MAC address")
#         exit(1)
#
# def process_file_for_encryption(plaintext_file, encrypted_file, sender_shared_key, sender_private_key):
#     encrypt_file(sender_shared_key, plaintext_file, encrypted_file)
#
#     with open(encrypted_file, 'rb') as file:
#         ciphertext = file.read()
#
#     signature = ecdsa_sign(sender_private_key, ciphertext)
#
#     with open(encrypted_file + ".sig", 'wb') as sig_file:
#         sig_file.write(signature)
#
# def process_file_for_decryption(encrypted_file, decrypted_file, receiver_shared_key, sender_public_key):
#     with open(encrypted_file, 'rb') as file:
#         ciphertext = file.read()
#
#     with open(encrypted_file + ".sig", 'rb') as sig_file:
#         signature = sig_file.read()
#
#     if ecdsa_verify(sender_public_key, ciphertext, signature):
#         decrypt_file(receiver_shared_key, encrypted_file, decrypted_file)
#
# def process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
#     if not os.path.exists(encrypted_folder_path):
#         os.makedirs(encrypted_folder_path)
#
#     with concurrent.futures.ThreadPoolExecutor() as executor:
#         futures = []
#         for filename in os.listdir(folder_path):
#             plaintext_file = os.path.join(folder_path, filename)
#             encrypted_file = os.path.join(encrypted_folder_path, filename + ".enc")
#             futures.append(executor.submit(process_file_for_encryption, plaintext_file, encrypted_file, sender_shared_key, sender_private_key))
#         concurrent.futures.wait(futures)
#
# def process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
#     if not os.path.exists(decrypted_folder_path):
#         os.makedirs(decrypted_folder_path)
#
#     with concurrent.futures.ThreadPoolExecutor() as executor:
#         futures = []
#         for filename in os.listdir(encrypted_folder_path):
#             if filename.endswith(".enc"):
#                 encrypted_file = os.path.join(encrypted_folder_path, filename)
#                 decrypted_file = os.path.join(decrypted_folder_path, filename[:-4])
#                 futures.append(executor.submit(process_file_for_decryption, encrypted_file, decrypted_file, receiver_shared_key, sender_public_key))
#         concurrent.futures.wait(futures)
#
# # Measure power consumption and RAM usage
# def measure_performance():
#     process = psutil.Process(os.getpid())
#     cpu_times = process.cpu_times()
#     memory_info = process.memory_info()
#
#     cpu_usage = cpu_times.user
#     memory_usage = memory_info.rss / (1024 * 1024)
#
#     return cpu_usage, memory_usage
#
# async def main():
#     print("..........HELO Performance Analysis..........")
#
#     # Measure performance before the process
#     cpu_before, memory_before = measure_performance()
#
#     start = time.time()
#
#     sender_private_key, sender_public_key = generate_keypair()
#     receiver_private_key, receiver_public_key = generate_keypair()
#
#     sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key)
#     receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key)
#
#     if sender_shared_key == receiver_shared_key:
#         folder_path = "(95 MB) Cityscapes Image Pairs"
#         encrypted_folder_path = "encrypted_file"
#         decrypted_folder_path = "decrypted_file"
#
#         process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)
#         process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)
#     else:
#         print("Alert: Intruder altered the key")
#         exit(1)
#
#     end = time.time()
#     total_time = end - start
#     print("Runtime: {:.2f} s".format(total_time))
#
#     # Measure performance after the process
#     cpu_after, memory_after = measure_performance()
#
#     cpu_result = cpu_after - cpu_before
#     memory_result = memory_after - memory_before
#
#     print("CPU time: {:.2f} seconds".format(cpu_result))
#     print("RAM usage: {:.2f} MB".format(memory_result))
#
# if __name__ == "__main__":
#     asyncio.run(main())





import asyncio
import os
import time
import psutil
import concurrent.futures
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

def chunk_size():
    #chunk_size = int(input("Enter chunk size in bytes (e.g. 1024 Byte for 1 KB): "))
    chunk_size = 1024
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

# Measure power consumption and RAM usage
def measure_performance():
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    memory_info = process.memory_info()

    cpu_usage = cpu_times.user
    memory_usage = memory_info.rss / (1024 * 1024)

    return cpu_usage, memory_usage

async def main():
    print("..........HELO Performance Analysis..........")

    # Measure performance before the process
    cpu_before, memory_before = measure_performance()

    start = time.time()

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

    end = time.time()
    total_time = end - start
    print("Runtime: {:.2f} s".format(total_time))

    # Measure performance after the process
    cpu_after, memory_after = measure_performance()

    cpu_result = cpu_after - cpu_before
    memory_result = memory_after - memory_before

    print("CPU time: {} seconds".format(cpu_result))
    print("RAM usage: {} MB".format(memory_result))

if __name__ == "__main__":
    asyncio.run(main())