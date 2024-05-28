// Generating public and private keypair for sender and reciver

FUNCTION generate_keypair()
    private_key = generate ECDSA private key using SECP256R1 curve
    public_key = derive public key from private key
    RETURN private_key, public_key
END FUNCTION

// Key exchange performs with ECDH and generate a common shared key for both sender and receiver

FUNCTION ecdh_key_exchange(private_key, public_key)
    shared_key = perform ECDH key exchange using private_key and public_key
    derived_key = derive key from shared_key using bcrypt with given salt, key length 32, and 100 rounds
    RETURN derived_key
END FUNCTION

// Ciphertext is digitally signed with ECDSA from the sender's end

FUNCTION ecdsa_sign(private_key, ciphertext)
    cipher_data = READ contents from ciphertext
    signature = sign cipher_data using private_key with ECDSA and SHA256
    RETURN signature
END FUNCTION

// Verifying the authenticity of ciphertext from the receiver's end

FUNCTION ecdsa_verify(public_key, ciphertext, signature)
    cipher_data = READ contents from ciphertext
    TRY:
        Verify signature using public_key, ciphertext, ECDSA, and SHA256
        RETURN True
    CATCH InvalidSignature:
        PRINT "Alert: Intruder altered the digital signature"
        EXIT with error
END FUNCTION

// Generating MAC for authenticating the message from the sender's end

FUNCTION generate_mac(key, ciphertext)
    mac = Generate Poly1305 MAC using key and ciphertext
    RETURN mac
END FUNCTION

// Verifying MAC from the receiver's end for legitimacy

FUNCTION verify_mac(key, ciphertext, provided_mac)
    computed_mac = Generate Poly1305 MAC using key and ciphertext
    RETURN (computed_mac == provided_mac)
END FUNCTION

// Encryption mechanism performs with ChaCha20

FUNCTION encryption(sender_shared_key, plaintext_file, encrypted_file)
    plaintext = READ contents from plaintext_file

    nonce = Generate 16 random bytes
    cipher = Initialize ChaCha20 cipher object with sender_shared_key and nonce
    encryptor = Create encryptor from cipher
    ciphertext = Encrypt plaintext using encryptor

    mac = generate_mac(key, ciphertext)

    WRITE nonce, ciphertext and mac to encrypted_file
END FUNCTION

// Decryption mechanism performs with ChaCha20

FUNCTION decryption(key, encrypted_file, decrypted_file)
    cipher_data = READ contents from encrypted_file

    nonce = EXTRACT first 16 bytes from cipher_data
    ciphertext = EXTRACT bytes from index 16 to -16 from cipher_data
    provided_mac = EXTRACT last 16 bytes from cipher_data

    IF verify_mac(key, ciphertext, provided_mac) is True THEN
        cipher = Initialize ChaCha20 cipher object with key and nonce
        decryptor = Create decryptor from cipher
        plaintext = Decrypt ciphertext using decryptor

        WRITE plaintext to decrypted_file
    ELSE
        PRINT "Alert: Intruder altered the MAC address"
        EXIT with error
    END IF
END FUNCTION


// DRIVER PROGRAM


// Sender and Receiver keypair
sender_private_key, sender_public_key = generate_keypair()
receiver_private_key, receiver_public_key = generate_keypair()

// ECDH key exchange
sender_shared_key = ecdh_key_exchange(sender_private_key, receiver_public_key)
receiver_shared_key = ecdh_key_exchange(receiver_private_key, sender_public_key)

// Files
plaintext_file = INPUT plaintext_file
encrypted_file = INPUT encrypted_file.bin
decrypted_file = INPUT decrypted_file

// Ensuring both shared keys are the same for successful key exchange
IF sender_shared_key == receiver_shared_key THEN
    // Encrypt the file
    encryption(sender_shared_key, input_file, encrypted_file)

    // Digital signature
    signature = ecdsa_sign(sender_private_key, encrypted_file)

    // Decrypt the file
    IF ecdsa_verify(sender_public_key, encrypted_file, signature) is True:
        decryption(receiver_shared_key, encrypted_file, decrypted_file)
ELSE
    PRINT "Alert: Intruder altered the key"
    EXIT with error
END IF