# import os
# import asyncio
# import xlsxwriter
# import numpy as np
# from cryptography.hazmat.primitives import hashes
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.poly1305 import Poly1305
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
#
#
# def generate_keypair():
#     private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
#     public_key = private_key.public_key()
#     return private_key, public_key
#
# def ecdh_key_exchange(private_key, public_key, salt):
#     shared_key = private_key.exchange(ec.ECDH(), public_key)
#     derived_key = HKDF(
#         algorithm=hashes.SHA3_256(),
#         length=32,
#         salt=salt,
#         info=b'handshake data'
#     ).derive(shared_key)
#     return derived_key
#
# def ecdsa_sign(private_key, ciphertext):
#     signature = private_key.sign(ciphertext, ec.ECDSA(hashes.SHA256()))
#     return signature
#
# def ecdsa_verify(public_key, ciphertext, signature):
#     try:
#         public_key.verify(signature, ciphertext, ec.ECDSA(hashes.SHA256()))
#         return True
#     except InvalidSignature:
#         print("Alert: Intruder altered the digital signature")
#         exit(1)
#
# def generate_mac(key, ciphertext):
#     mac = Poly1305.generate_tag(key, ciphertext)
#     return mac
#
# def verify_mac(key, ciphertext, provided_mac):
#     computed_mac = Poly1305.generate_tag(key, ciphertext)
#     return computed_mac == provided_mac
#
# def encryption(key, plaintext):
#     nonce = os.urandom(16)
#     cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(plaintext) + encryptor.finalize()
#     mac = generate_mac(key, ciphertext)
#     return nonce + ciphertext + mac
#
# def decryption(key, encrypted_data):
#     nonce = encrypted_data[:16]
#     ciphertext = encrypted_data[16:-16]
#     provided_mac = encrypted_data[-16:]
#
#     if verify_mac(key, ciphertext, provided_mac):
#         cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
#         decryptor = cipher.decryptor()
#         plaintext = decryptor.update(ciphertext) + decryptor.finalize()
#         return plaintext
#     else:
#         print("Alert: Intruder altered the MAC address")
#         exit(1)
#
# def flip_bit(byte_array, bit_position):
#     byte_index = bit_position // 8
#     bit_index = bit_position % 8
#     byte_array[byte_index] ^= (1 << bit_index)
#     return byte_array
#
# def calculate_avalanche_effect(ciphertext1, ciphertext2):
#     diff = np.sum(np.unpackbits(np.frombuffer(ciphertext1, dtype=np.uint8) ^ np.frombuffer(ciphertext2, dtype=np.uint8)))
#     return diff
#
# def save_results_to_excel(results, filename):
#     workbook = xlsxwriter.Workbook(filename)
#     worksheet = workbook.add_worksheet()
#     worksheet.write('A1', 'Bit Position')
#     worksheet.write('B1', 'Avalanche Effect (%)')
#
#     for i, result in enumerate(results):
#         worksheet.write(i + 1, 0, result[0])
#         worksheet.write(i + 1, 1, result[1])
#
#     workbook.close()
#
# async def main():
#     # Sender's keypair
#     sender_private_key, sender_public_key = generate_keypair()
#
#     # Receiver's keypair
#     receiver_private_key, receiver_public_key = generate_keypair()
#
#     salt = os.urandom(16)
#
#     sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key, salt)
#     receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key, salt)
#
#     # Files
#     plaintext_file = "(68 KB) Selected Macroeconomic and Financial Indicators - Eastern Caribbean Central Bank.xlsx"
#     encrypted_file = "encrypted_file.bin"
#     decrypted_file = "decrypted_file"
#
#     # Read original plaintext as binary
#     with open(plaintext_file, 'rb') as file:
#         plaintext = file.read()
#
#     # Ensuring both shared keys are the same for successful key exchange
#     if sender_shared_key == receiver_shared_key:
#         # Encrypt the file
#         encrypted_data = encryption(sender_shared_key, plaintext)
#         with open(encrypted_file, 'wb') as file:
#             file.write(encrypted_data)
#
#         # Digital signature
#         signature = ecdsa_sign(sender_private_key, encrypted_data)
#
#         # Verifying signature
#         if ecdsa_verify(sender_public_key, encrypted_data, signature):
#             # Decrypt the file
#             decrypted_plaintext = decryption(receiver_shared_key, encrypted_data)
#             with open(decrypted_file, 'wb') as file:
#                 file.write(decrypted_plaintext)
#         else:
#             print("Alert: Intruder altered the digital signature")
#             exit(1)
#     else:
#         print("Alert: Intruder altered the key")
#         exit(1)
#
#     # Avalanche effect analysis
#     num_bits_to_flip = 21
#     results = []
#     chunk_size = 1024  # Process in 1KB chunks
#
#     for i in range(0, len(plaintext), chunk_size):
#         chunk = plaintext[i:i+chunk_size]
#
#         # Original encryption
#         original_ciphertext = encryption(sender_shared_key, chunk)
#
#         # Loop through bit positions to flip within the chunk
#         for bit_position in range(num_bits_to_flip):
#             modified_chunk = flip_bit(bytearray(chunk), bit_position)
#             modified_ciphertext = encryption(sender_shared_key, modified_chunk)
#             diff = calculate_avalanche_effect(original_ciphertext, modified_ciphertext)
#             diff_percentage = (diff / (len(original_ciphertext) * 8)) * 100
#             results.append([bit_position + i*8, diff_percentage])
#
#     # Save results to an Excel file
#     save_results_to_excel(results, "avalanche_effect_results.xlsx")
#
# if __name__ == "__main__":
#     asyncio.run(main())




import asyncio
import os
import concurrent.futures
import xlsxwriter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

def chunk_size():
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

def process_chunked_file_for_encryption(plaintext_file, encrypted_file, sender_shared_key, sender_private_key, avalanche_file):
    chunked_data = chunk_size()  # Get chunk size from user input

    avalanche_results = {i: 0 for i in range(21)}  # Dictionary to store avalanche effect counts for bit positions 0 to 20
    total_bits = 0  # To keep track of total bits processed

    nonce = generate_token()
    cipher = Cipher(algorithms.ChaCha20(sender_shared_key, nonce), mode=None)
    encryptor = cipher.encryptor()

    with open(plaintext_file, 'rb') as infile, open(encrypted_file, 'wb') as outfile:
        outfile.write(nonce)
        while chunk := infile.read(chunked_data):
            total_bits += len(chunk) * 8

            original_plaintext = int.from_bytes(chunk, byteorder='big')
            ciphertext = encryptor.update(chunk)
            outfile.write(ciphertext)

            encrypted_chunk = int.from_bytes(ciphertext, byteorder='big')

            # Calculate avalanche effect for each bit position
            for bit_position in range(21):
                modified_plaintext = original_plaintext ^ (1 << bit_position)
                modified_chunk = modified_plaintext.to_bytes((modified_plaintext.bit_length() + 7) // 8, byteorder='big')
                modified_ciphertext = encryptor.update(modified_chunk)
                modified_encrypted_chunk = int.from_bytes(modified_ciphertext, byteorder='big')

                # Calculate bit differences
                differing_bits = bin(encrypted_chunk ^ modified_encrypted_chunk).count('1')
                avalanche_results[bit_position] += differing_bits

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

    # Write avalanche effect results to Excel file
    workbook = xlsxwriter.Workbook(avalanche_file)
    worksheet = workbook.add_worksheet()

    # Write headers
    worksheet.write(0, 0, 'Bit Position')
    worksheet.write(0, 1, 'Avalanche Effect (%)')

    # Write data
    for bit_position, count in avalanche_results.items():
        percentage = (count / total_bits) * 100
        worksheet.write(bit_position + 1, 0, bit_position)
        worksheet.write(bit_position + 1, 1, percentage)

    workbook.close()

# def process_chunked_file_for_decryption(encrypted_file, decrypted_file, receiver_shared_key, sender_public_key):
#     # Verifying the signature
#     with open(encrypted_file, 'rb') as file:
#         ciphertext = file.read()
#
#     with open(encrypted_file + ".sig", 'rb') as sig_file:
#         signature = sig_file.read()
#
#     if ecdsa_verify(sender_public_key, ciphertext, signature):
#         with open(encrypted_file, 'rb') as file:
#             nonce = file.read(16)
#             data = file.read()
#
#         ciphertext = data[:-16]
#         provided_mac = data[-16:]
#
#         if verify_mac(receiver_shared_key, ciphertext, provided_mac):
#             cipher = Cipher(algorithms.ChaCha20(receiver_shared_key, nonce), mode=None)
#             decryptor = cipher.decryptor()
#
#             with open(decrypted_file, 'wb') as outfile:
#                 outfile.write(decryptor.update(ciphertext))
#                 outfile.write(decryptor.finalize())
#         else:
#             print("Alert: Intruder altered the MAC address")
#             exit(1)
#     else:
#         print("Alert: Signature verification failed")
#         exit(1)

def multithreading_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for filename in os.listdir(folder_path):
            plaintext_file = os.path.join(folder_path, filename)
            encrypted_file = os.path.join(encrypted_folder_path, filename + ".enc")
            avalanche_file = os.path.join(encrypted_folder_path, filename + "_avalanche.xlsx")
            futures.append(executor.submit(process_chunked_file_for_encryption, plaintext_file, encrypted_file, sender_shared_key, sender_private_key, avalanche_file))
        concurrent.futures.wait(futures)

# def multithreading_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
#     with concurrent.futures.ThreadPoolExecutor() as executor:
#         futures = []
#         for filename in os.listdir(encrypted_folder_path):
#             if filename.endswith(".enc"):
#                 encrypted_file = os.path.join(encrypted_folder_path, filename)
#                 decrypted_file = os.path.join(decrypted_folder_path, filename[:-4])
#                 futures.append(executor.submit(process_chunked_file_for_decryption, encrypted_file, decrypted_file, receiver_shared_key, sender_public_key))
#         concurrent.futures.wait(futures)

def process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key):
    if not os.path.exists(encrypted_folder_path):
        os.makedirs(encrypted_folder_path)

    multithreading_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)

# def process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key):
#     if not os.path.exists(decrypted_folder_path):
#         os.makedirs(decrypted_folder_path)
#
#     multithreading_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)

async def main():
    print("NOTE: Chunk size will be initialized as bytes by default.\nHowever, you need to convert bytes it into another unit.\n")

    sender_private_key, sender_public_key = generate_keypair()
    receiver_private_key, receiver_public_key = generate_keypair()

    salt = os.urandom(16)

    sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key, salt)
    receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key, salt)

    if sender_shared_key == receiver_shared_key:
        folder_path = "original_files"
        encrypted_folder_path = "encrypted_files"
        # decrypted_folder_path = "decrypted_files"

        process_folder_for_encryption(folder_path, encrypted_folder_path, sender_shared_key, sender_private_key)
        # process_folder_for_decryption(encrypted_folder_path, decrypted_folder_path, receiver_shared_key, sender_public_key)
    else:
        print("Alert: Intruder altered the key")
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())