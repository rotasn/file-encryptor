**File Encryptor**
A secure desktop application for encrypting and decrypting files with password protection.

**Features**

- Strong Encryption: Uses Fernet symmetric encryption with PBKDF2 key derivation
- Password Protection: Secure your files with password-based encryption
- Modern UI: Clean and intuitive interface built with PyQt5
- File Backup: Optional automatic backup creation before encryption/decryption
- Password Strength Meter: Visual indicator of password security
- Encryption Detection: Automatically detects if a file appears to be encrypted

**Prerequisites**
+ Python 3.8 or higher
+ pip (Python package installer)

**Option 1: From Source**

1. Clone the repository:
```
git clone https://github.com/rotasn/file-encryptor.git
cd file-encryptor
```
2. Create a virtual environment:

```
python -m venv venv
# On Windows
venv\Scripts\activate
```
3. Install dependencies
```
pip install -r requirements.txt
```
4. Run the application:
```
python file_encryptor.py
```

**Option 2: Standalone Executable**
 Download the latest executable from the Releases page.

**Usage**

1. Select a File: Click "Browse" to select the file you want to encrypt or decrypt
2. Enter Password: Type a secure password (and confirm it for encryption)
3. Optional: Check "Create backup" to make a backup of your file before processing
4. Process: Click "Encrypt" to secure your file or "Decrypt" to restore it

**How It Works**
+ Encryption: The app generates a random salt, derives a key from your password using PBKDF2, and encrypts your file using Fernet symmetric encryption
+ Decryption: The app extracts the salt from the encrypted file, derives the same key using your password, and decrypts the file content
+ Backup: If enabled, the app creates a .backup file before modifying the original

**Security**

- No Password Storage: Your password is never stored or saved
- Strong Key Derivation: Uses PBKDF2 with SHA-256 and 100,000 iterations
- Unique Salt: Each encryption uses a new random salt for added security

**Acknowledgments**

- PyQt5 for the UI framework
- [cryptography](https://cryptography.io/en/latest/) for the encryption functionality
