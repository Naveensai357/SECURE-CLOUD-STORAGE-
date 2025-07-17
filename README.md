# 🔐 Secure Cloud Storage with RSA, 3DES, and SHA-256

A Python-based simulation of secure cloud storage using classical cryptographic techniques:

- 🔑 **RSA** for key generation and digital signatures  
- 🔒 **3DES** for file encryption and decryption  
- 🧾 **SHA-256** for message digest and data integrity verification  

> Developed as part of the 19CSE331 Cryptography Practical Assignment – Group 8

---

## 📘 Project Overview

This project demonstrates how secure file storage can be implemented by combining symmetric and asymmetric cryptography with hashing:

- **Triple DES (3DES)** encrypts the file to ensure confidentiality  
- **RSA** is used for generating key pairs and signing the file  
- **SHA-256** hashes the file content to verify integrity  
- The system simulates **upload and download** with signature verification  

---

## 🔧 Features

- ✅ RSA key pair generation (user-specified primes)  
- ✅ Triple DES encryption/decryption with 3 independent keys  
- ✅ SHA-256 based digital signature using RSA private key  
- ✅ Signature verification using RSA public key  
- ✅ Upload: Encrypt + Sign file  
- ✅ Download: Decrypt + Verify file  

---

## 🚀 How to Run

### 1. Run the Code

bash
python3 crypto_project_code.py

2. Follow the Prompts
Enter two prime numbers (for RSA key generation)

Enter a public exponent (e)

Enter three DES keys (as integers)

Choose:
1. Upload File or
2. Download File

💻 Dependencies
Only standard Python libraries are used:

os

hashlib

struct

✅ Tested on Python 3.6+

📸 Screenshots
<details> <summary>Click to Expand</summary>
🔐 Encryption Interface
(Screenshot of file encryption using 3DES and signature generation)

🔓 Decryption & Verification
(Screenshot of file decryption and RSA signature validation)

</details>
🧪 Sample Workflow
🔐 Upload Process
Encrypt file using 3DES with key1 → key2 → key3

Hash the original file using SHA-256

Sign the hash using RSA private key

Save:

.enc file (encrypted content)

.sig file (digital signature)

🔓 Download Process
Decrypt the .enc file using 3DES

Hash the decrypted file and compare with decrypted signature using RSA public key

If valid, save the file as .dec

📌 Observations
🔒 Strong educational value combining RSA, 3DES, and hashing

❗ Uses simplified DES logic (not secure for real-world use)

📉 May be slow for large files

🚫 No standard padding schemes like PKCS#1 or PKCS#7

📈 Future Improvements
🔄 Replace 3DES → AES

🔁 Replace RSA → ECDSA for signatures

🖥️ Add GUI interface

🔐 Implement proper key validation and padding standards

⚠️ Improve error handling and input validation
