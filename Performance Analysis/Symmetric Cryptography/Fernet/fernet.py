from cryptography.fernet import Fernet
import hashlib
import base64
import psutil
import os
import time


# Function to derive a Fernet key from a password using SHA-256
def derive_key(password):
    # Use SHA-256 to hash the password
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    key = sha256.digest()  # Use digest() to get the raw bytes

    # Convert the raw bytes to base64 encoded bytes
    key_base64 = base64.urlsafe_b64encode(key)

    return key_base64


# Encrypt a file
def encrypt_file(file_path, fernet, output_folder_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    encrypted_file_path = os.path.join(output_folder_path, os.path.basename(file_path)) + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)


# Decrypt a file
def decrypt_file(file_path, fernet, output_folder_path):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_file_path = os.path.join(output_folder_path, os.path.basename(file_path))[:-4]
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)


# Measure performance
def measure_performance():
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    memory_info = process.memory_info()

    cpu_usage = cpu_times.user
    memory_usage = memory_info.rss / (1024 * 1024)

    return cpu_usage, memory_usage


# Example usage
if __name__ == "__main__":
    print(".....Fernet Performance Analysis.....")

    cpu_before, memory_before = measure_performance()

    start = time.time()
    input_folder_path = 'original file'
    encrypted_folder_path = os.path.join(input_folder_path, 'encrypted')
    decrypted_folder_path = os.path.join(input_folder_path, 'decrypted')
    password = str(os.urandom(32))

    os.makedirs(encrypted_folder_path, exist_ok=True)
    os.makedirs(decrypted_folder_path, exist_ok=True)

    # Derive key using SHA-256 from password
    key = derive_key(password)
    fernet = Fernet(key)

    # Process files in the input folder
    for root, _, files in os.walk(input_folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.enc'):
                decrypt_file(file_path, fernet, decrypted_folder_path)
            else:
                encrypt_file(file_path, fernet, encrypted_folder_path)

    end = time.time()
    total_time = end - start
    print("Runtime: {:.2f} s".format(total_time))

    cpu_after, memory_after = measure_performance()

    cpu_result = cpu_after - cpu_before
    memory_result = memory_after - memory_before

    print("CPU time: {:.2f} seconds".format(cpu_result))
    print("RAM usage: {:.2f} MB".format(memory_result))
