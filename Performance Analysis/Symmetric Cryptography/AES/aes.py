import time
import os
import psutil
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Function to generate a random AES key
def generate_aes_key(password):
    # Hash the password using SHA-256
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    hashed_key = sha256.digest()

    # Use the first 32 bytes (256 bits) of the hashed key for AES
    aes_key = hashed_key[:32]
    return aes_key

# Function to encrypt a file using AES
def encrypt_file(file_path, aes_key, output_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    iv = os.urandom(16)  # Initialization vector for AES

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as file:
        file.write(iv)
        file.write(encrypted_data)

    return iv, encrypted_data

# Function to decrypt a file using AES
def decrypt_file(encrypted_file_path, aes_key, output_path):
    with open(encrypted_file_path, 'rb') as file:
        iv = file.read(16)
        encrypted_data = file.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as file:
        file.write(data)

    return data

# Function to encrypt all files in a folder
def encrypt_folder(input_folder_path, output_folder_path, password):
    aes_key = generate_aes_key(password)

    for root, dirs, files in os.walk(input_folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, input_folder_path)
            output_path = os.path.join(output_folder_path, relative_path) + '.enc'
            encrypt_file(file_path, aes_key, output_path)

# Function to decrypt all files in a folder
def decrypt_folder(input_folder_path, output_folder_path, password):
    aes_key = generate_aes_key(password)

    for root, dirs, files in os.walk(input_folder_path):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, input_folder_path)
                original_file_path = os.path.join(output_folder_path, relative_path)[:-4]  # remove .enc extension
                decrypt_file(file_path, aes_key, original_file_path)

def measure_performance():
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    memory_info = process.memory_info()

    cpu_usage = cpu_times.user
    memory_usage = memory_info.rss / (1024 * 1024)

    return cpu_usage, memory_usage

# Example usage
if __name__ == "__main__":
    cpu_before = measure_performance()[0]
    memory_before = measure_performance()[1]
    start = time.time()
    print("-----AES Performance Analysis-----")

    # Define folder paths
    input_folder_path = 'original file'
    encrypted_folder_path = os.path.join(input_folder_path, 'encrypted')
    decrypted_folder_path = os.path.join(input_folder_path, 'decrypted')

    password = str(os.urandom(32))  # Generate a random password for AES key derivation

    # os.makedirs(encrypted_folder_path, exist_ok=True)
    # os.makedirs(decrypted_folder_path, exist_ok=True)

    # Encrypt folder
    encrypt_folder(input_folder_path, encrypted_folder_path, password)

    # Decrypt folder
    decrypt_folder(encrypted_folder_path, decrypted_folder_path, password)

    end = time.time()
    total_time = end - start
    print("Runtime: {:.2f} s".format(total_time))

    cpu_after = measure_performance()[0]
    memory_after = measure_performance()[1]

    cpu_result = cpu_after - cpu_before
    memory_result = memory_after - memory_before

    print("CPU time: {:.2f} seconds".format(cpu_result))
    print("RAM usage: {:.2f} MB".format(memory_result))
