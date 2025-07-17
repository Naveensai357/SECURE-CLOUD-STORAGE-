import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import hashlib

# Global variables
key_pair = RSA.generate(2048)
public_key = key_pair.publickey()
private_key = key_pair
ciphertext = None
symmetric_key = None
nonce = None
file_hash = None
signature = None

def encrypt_file():
    global ciphertext, symmetric_key, nonce, file_hash, signature

    # Get file data from user
    file_path = filedialog.askopenfilename()
    if not file_path:
        messagebox.showerror("Error", "No file selected.")
        return

    with open(file_path, "rb") as file:
        file_data = file.read()

    # 1. Encrypt the file using 3DES
    symmetric_key = DES3.adjust_key_parity(get_random_bytes(24))
    cipher = DES3.new(symmetric_key, DES3.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(file_data)

    # 2. Hash the original data
    file_hash = hashlib.sha256(file_data).hexdigest()

    # 3. Sign the hash with the private key
    h = SHA256.new(file_data)
    signature = pkcs1_15.new(private_key).sign(h)

    messagebox.showinfo("Success", "File encrypted successfully!")

def decrypt_file():
    global ciphertext, symmetric_key, nonce

    # Check if data is encrypted
    if not ciphertext or not symmetric_key or not nonce:
        messagebox.showerror("Error", "No encrypted data available.")
        return

    # Decrypt the file
    cipher = DES3.new(symmetric_key, DES3.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(ciphertext)

    # Verify data integrity
    received_hash = hashlib.sha256(decrypted_data).hexdigest()
    integrity_check = received_hash == file_hash

    # Verify signature
    h = SHA256.new(decrypted_data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        signature_check = True
    except (ValueError, TypeError):
        signature_check = False

    # Save decrypted data to file
    save_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if save_path:
        with open(save_path, "wb") as file:
            file.write(decrypted_data)

    # Display results
    result = "Decryption Successful!\n"
    result += f"Integrity Check: {'Passed' if integrity_check else 'Failed'}\n"
    result += f"Signature Verification: {'Valid' if signature_check else 'Invalid'}"
    messagebox.showinfo("Decryption Results", result)

def show_keys():
    """Display the RSA public and private keys."""
    key_window = tk.Toplevel(root)
    key_window.title("RSA Keys")
    key_window.geometry("600x400")

    public_key_label = tk.Label(key_window, text="Public Key:")
    public_key_label.pack(anchor="w", padx=10, pady=5)
    public_key_text = tk.Text(key_window, wrap="word", height=10)
    public_key_text.insert("1.0", public_key.export_key().decode())
    public_key_text.config(state="disabled")
    public_key_text.pack(padx=10, pady=5)

    private_key_label = tk.Label(key_window, text="Private Key:")
    private_key_label.pack(anchor="w", padx=10, pady=5)
    private_key_text = tk.Text(key_window, wrap="word", height=10)
    private_key_text.insert("1.0", private_key.export_key().decode())
    private_key_text.config(state="disabled")
    private_key_text.pack(padx=10, pady=5)

# Create the main window
root = tk.Tk()
root.title("Secure File Transfer")
root.geometry("400x300")

# Add buttons
encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_file)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_button.pack(pady=10)

keys_button = tk.Button(root, text="Show Keys", command=show_keys)
keys_button.pack(pady=10)

exit_button = tk.Button(root, text="Exit", command=root.quit)
exit_button.pack(pady=10)

# Run the GUI event loop
root.mainloop()