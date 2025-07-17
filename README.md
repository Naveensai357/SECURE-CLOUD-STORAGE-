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

