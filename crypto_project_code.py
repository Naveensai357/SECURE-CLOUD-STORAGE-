import os
import hashlib
import struct

# Helper: Modular Inverse for RSA Key Generation
def mod_inverse(a, m):
    """Find the modular inverse of a under modulus m."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# 1. RSA Key Generation
def generate_rsa_keys():
    """Generates RSA public and private keys."""
    print("\nRSA Key Generation")
    p = int(input("Enter a prime number (p): "))
    q = int(input("Enter another prime number (q): "))
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = int(input("Enter a public key exponent (e): "))
    d = mod_inverse(e, phi)
    
    if d is None:
        print("Error: Invalid e. Modular inverse doesn't exist.")
        return None, None

    print(f"Keys generated successfully!\nPublic Key: (e={e}, n={n})\nPrivate Key: (d={d}, n={n})")
    return (e, n), (d, n)

# 2. Triple DES Encryption
def generate_round_keys(key, rounds=16):
    return [(key >> (i % 8)) & 0xFF for i in range(rounds)]

def feistel_function(right_half, round_key):
    return ((right_half ^ round_key) << 1) & 0xFF | ((right_half ^ round_key) >> 7)

def des_encrypt_block(block, key):
    """Simplified Feistel DES with permutations."""
    if len(block) != 8:
        raise ValueError("Block size must be 8 bytes")
    rounds = 16
    round_keys = generate_round_keys(key, rounds)
    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")
    
    for rk in round_keys:
        temp = right
        right = left ^ feistel_function(right, rk)
        left = temp
    
    return (right.to_bytes(4, "big") + left.to_bytes(4, "big"))

def triple_des_encrypt(data, key1, key2, key3):
    encrypted = b""
    for i in range(0, len(data), 8):
        block = data[i:i+8].ljust(8, b"\0")
        block = des_encrypt_block(block, key1)
        block = des_encrypt_block(block, key2)
        block = des_encrypt_block(block, key3)
        encrypted += block
    return encrypted

def triple_des_decrypt(data, key1, key2, key3):
    decrypted = b""
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        block = des_encrypt_block(block, key3)
        block = des_encrypt_block(block, key2)
        block = des_encrypt_block(block, key1)
        decrypted += block
    return decrypted.rstrip(b"\0")

# 3. RSA Signing and Verification with Hashing
def rsa_encrypt(data, key, n):
    return [pow(byte, key, n) for byte in data]

def rsa_decrypt(data, key, n):
    return [pow(byte, key, n) for byte in data]

def sha256_hash(data):
    """Generates SHA-256 hash of the data."""
    return hashlib.sha256(data).digest()

def sign_data(data, private_key):
    """Sign the hash of the data."""
    data_hash = sha256_hash(data)
    signature = rsa_encrypt(data_hash, *private_key)
    return signature

def verify_signature(data, signature, public_key):
    """Verify the RSA signature with hashing."""
    data_hash = sha256_hash(data)
    decrypted_hash = rsa_decrypt(signature, *public_key)
    return data_hash == decrypted_hash

# 4. Cloud Storage Simulation
def upload_file(file_path, key1, key2, key3, private_key):
    if not os.path.exists(file_path):
        print("Error: File does not exist.")
        return
    with open(file_path, "rb") as file:
        data = file.read()
    
    # Encrypt file data
    encrypted_data = triple_des_encrypt(data, key1, key2, key3)
    
    # Generate signature based on SHA-256 hash
    signature = sign_data(data, private_key)
    
    # Save encrypted data
    enc_file = file_path + ".enc"
    with open(enc_file, "wb") as ef:
        ef.write(encrypted_data)
    
    # Save signature as integers
    sig_file = file_path + ".sig"
    with open(sig_file, "w") as sf:
        sf.write(" ".join(map(str, signature)))
    
    print(f"File encrypted and uploaded as '{enc_file}', signature saved as '{sig_file}'.")

def download_file(enc_file_path, sig_file_path, key1, key2, key3, public_key):
    if not os.path.exists(enc_file_path) or not os.path.exists(sig_file_path):
        print("Error: Encrypted file or signature file missing.")
        return
    with open(enc_file_path, "rb") as ef:
        encrypted_data = ef.read()
    with open(sig_file_path, "r") as sf:
        signature = list(map(int, sf.read().split()))
    
    # Decrypt file data
    decrypted_data = triple_des_decrypt(encrypted_data, key1, key2, key3)
    
    # Verify signature with SHA-256 hash
    if verify_signature(decrypted_data, signature, public_key):
        print("Signature verification successful. File is authentic.")
    else:
        print("Signature verification failed!")
    
    # Save decrypted data
    dec_file = enc_file_path.replace(".enc", ".dec")
    with open(dec_file, "wb") as df:
        df.write(decrypted_data)
    print(f"Decrypted file saved as '{dec_file}'.")

# 5. Main Function
def main():
    print("Secure Cloud Storage System with Hashing")
    public_key, private_key = generate_rsa_keys()
    if not public_key or not private_key:
        print("RSA key generation failed.")
        return
    
    key1, key2, key3 = [int(input(f"Enter 3DES key {i+1}: ")) for i in range(3)]
    
    while True:
        print("\nOptions:")
        print("1. Upload File")
        print("2. Download File")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()
        
        if choice == "1":
            file_path = input("Enter the file path: ").strip()
            upload_file(file_path, key1, key2, key3, private_key)
        elif choice == "2":
            enc_file_path = input("Enter the encrypted file path: ").strip()
            sig_file_path = input("Enter the signature file path: ").strip()
            download_file(enc_file_path, sig_file_path, key1, key2, key3, public_key)
        elif choice == "3":
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
