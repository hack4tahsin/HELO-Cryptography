from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.poly1305 import Poly1305
import time
import os
import psutil
from warnings import filterwarnings

start = time.time()

filterwarnings("ignore")


def generate_salt():
    return os.urandom(16)


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt(plaintext, key):
    iv = os.urandom(8)  # Initialization vector
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to be a multiple of the block size (8 bytes for Blowfish)
    padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    mac = Poly1305(key)
    mac.update(ciphertext)
    tag = mac.finalize()

    return iv + ciphertext, tag


def decrypt(ciphertext, key):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]

    mac = Poly1305(key)
    mac.update(ciphertext)
    tag = mac.finalize()

    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return plaintext, tag


def process_folder_for_encryption(folder_path, key):
    encrypted_folder_path = folder_path + '_encrypted'
    if not os.path.exists(encrypted_folder_path):
        os.makedirs(encrypted_folder_path)

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                plaintext = file.read()

            ciphertext, tag = encrypt(plaintext, key)
            encrypted_file_path = os.path.join(encrypted_folder_path, filename + '.enc')

            with open(encrypted_file_path, 'wb') as file:
                file.write(ciphertext)


def process_folder_for_decryption(encrypted_folder_path, key):
    decrypted_folder_path = encrypted_folder_path.replace('_encrypted', '_decrypted')
    if not os.path.exists(decrypted_folder_path):
        os.makedirs(decrypted_folder_path)

    for filename in os.listdir(encrypted_folder_path):
        encrypted_file_path = os.path.join(encrypted_folder_path, filename)
        if os.path.isfile(encrypted_file_path) and filename.endswith('.enc'):
            with open(encrypted_file_path, 'rb') as file:
                ciphertext = file.read()

            decrypted_data, tag = decrypt(ciphertext, key)
            decrypted_file_path = os.path.join(decrypted_folder_path, filename.replace('.enc', ''))

            with open(decrypted_file_path, 'wb') as file:
                file.write(decrypted_data)


def measure_performance():
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    memory_info = process.memory_info()

    cpu_usage = cpu_times.user
    memory_usage = memory_info.rss / (1024 * 1024)

    return cpu_usage, memory_usage


# Example usage:
if __name__ == "__main__":
    cpu_before = measure_performance()[0]
    memory_before = measure_performance()[1]

    print("-----Blowfish Performance Analysis-----")

    password = os.urandom(32)
    salt = generate_salt()
    key = derive_key(password, salt)

    folder_path = 'original file'  # Replace with the path to your folder

    # Encrypt folder
    process_folder_for_encryption(folder_path, key)

    # Decrypt folder
    process_folder_for_decryption(folder_path + '_encrypted', key)

    end = time.time()
    total_time = end - start
    print("Runtime: {:.2f} s".format(total_time))

    cpu_after = measure_performance()[0]
    memory_after = measure_performance()[1]

    cpu_result = cpu_after - cpu_before
    memory_result = memory_after - memory_before

    print("CPU time: {:.2f} seconds".format(cpu_result))
    print("RAM usage: {:.2f} MB".format(memory_result))
