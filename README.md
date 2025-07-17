# SECURE-CLOUD-STORAGE-
# 🔐 Secure Cloud Storage with RSA, 3DES, and SHA-256

A Python-based simulation of secure cloud storage using classical cryptographic techniques:

- 🔑 **RSA** for key generation and digital signatures
- 🔒 **3DES** for file encryption and decryption
- 🧾 **SHA-256** for message digest and data integrity verification

> Developed as part of the 19CSE331 Cryptography Practical Assignment – Group 8

---

## 📘 Project Overview

This project demonstrates how secure file storage can be implemented by combining symmetric and asymmetric cryptography with hashing:

- Files are encrypted using **Triple DES (3DES)** for confidentiality
- Digital signatures are created using **RSA** to ensure authenticity
- **SHA-256** hashing ensures data integrity
- Simulates **upload and download** with verification

---

## 🔧 Features

- ✅ RSA key pair generation (based on user-input primes)
- ✅ Triple DES block-based encryption with three keys
- ✅ SHA-256 based digital signatures using RSA private key
- ✅ Signature verification using RSA public key
- ✅ File upload: Encrypt + Sign
- ✅ File download: Decrypt + Verify

---
2. Run the Code
bash
Copy
Edit
python3 crypto_project_code.py
3. Follow On-Screen Prompts
Enter two prime numbers (for RSA)

Enter public exponent e

Enter 3 DES keys (integers)

Choose: 1. Upload File or 2. Download File

💻 Dependencies
Only standard Python libraries are used:

os

hashlib

struct

Tested on Python 3.6+

📸 Screenshots
<details> <summary>Click to Expand</summary>
Encryption Example

Decryption & Verification

</details>
🧪 Sample Workflow
🔐 Upload
Encrypts file with 3DES

Hashes file with SHA-256

Signs the hash using RSA private key

Saves .enc and .sig files

🔓 Download
Decrypts .enc file with 3DES

Verifies .sig using RSA public key and SHA-256

If valid, writes the decrypted .dec file


📌 Observations
🔒 Strong educational value combining multiple crypto primitives

❗ Uses simplified DES (not for production)

📉 May have performance issues for large files

🚫 Lacks padding standards (like PKCS#1 or PKCS#7)

💡 Can be extended with AES, ECDSA, and proper padding

📈 Future Improvements
Switch from 3DES → AES

Replace RSA → ECDSA for signatures

Add GUI interface

Implement proper key validation and error handling

Adopt padding schemes and real-world secure coding practices

