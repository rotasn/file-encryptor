import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QFileDialog, QWidget, QMessageBox, QFrame,
                            QProgressBar, QStackedWidget, QCheckBox)
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QPalette, QFont, QIcon
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os.path

class StyledButton(QPushButton):
    def __init__(self, text, primary=False):
        super().__init__(text)
        self.setMinimumHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        
        if primary:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #2a9d8f;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #218c7e;
                }
                QPushButton:pressed {
                    background-color: #1e7d71;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #e9e9e9;
                    color: #333;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                }
                QPushButton:hover {
                    background-color: #d4d4d4;
                }
                QPushButton:pressed {
                    background-color: #c1c1c1;
                }
            """)

class FileEncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.selected_file_path = None
        self.is_file_encrypted = False
        
    def initUI(self):
        self.setWindowTitle('File Encryptor')
        self.setGeometry(300, 300, 600, 400)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            QLabel {
                color: #333;
                font-size: 14px;
            }
            QLineEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 8px;
                background: white;
                selection-background-color: #2a9d8f;
                min-height: 20px;
            }
            QFrame#card {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
            QCheckBox {
                color: #333;
                font-size: 14px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:checked {
                background-color: #2a9d8f;
                border: 2px solid #2a9d8f;
                border-radius: 3px;
            }
            QCheckBox::indicator:unchecked {
                background-color: white;
                border: 2px solid #ccc;
                border-radius: 3px;
            }
        """)
        
        # central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # card-like container
        card = QFrame()
        card.setObjectName("card")
        card.setFrameShape(QFrame.StyledPanel)
        card.setFrameShadow(QFrame.Raised)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(15)
        
        # App title
        title_label = QLabel('File Encryption Tool')
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #264653; margin-bottom: 10px;")
        title_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel('Securely encrypt and decrypt your files with a password')
        desc_label.setStyleSheet("font-size: 14px; color: #666; margin-bottom: 10px;")
        desc_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(desc_label)
        
        # separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("background-color: #e0e0e0;")
        card_layout.addWidget(separator)
        
        # File selection row
        file_layout = QHBoxLayout()
        self.file_label = QLabel('No file selected')
        self.file_label.setStyleSheet("""
            padding: 8px;
            background-color: #f2f2f2;
            border-radius: 4px;
            min-height: 20px;
        """)
        self.browse_button = StyledButton('Browse')
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(QLabel('File:'))
        file_layout.addWidget(self.file_label, 1)
        file_layout.addWidget(self.browse_button)
        card_layout.addLayout(file_layout)
        
        # File status indicator
        self.file_status = QLabel('')
        self.file_status.setAlignment(Qt.AlignCenter)
        self.file_status.setStyleSheet("font-style: italic; color: #666;")
        card_layout.addWidget(self.file_status)
        
        # Password
        password_layout = QVBoxLayout()
        password_header = QHBoxLayout()
        password_header.addWidget(QLabel('Password:'))
        password_layout.addLayout(password_header)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your secure password")
        password_layout.addWidget(self.password_input)
        
        # Confirm password
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm your password")
        password_layout.addWidget(self.confirm_password_input)
        
        # Password match indicator
        self.password_match_label = QLabel('')
        self.password_match_label.setAlignment(Qt.AlignRight)
        password_layout.addWidget(self.password_match_label)
        
        # Connect password fields to validation function
        self.password_input.textChanged.connect(self.validate_passwords)
        self.confirm_password_input.textChanged.connect(self.validate_passwords)
        
        card_layout.addLayout(password_layout)
        
        # Password strength indicator
        password_strength_layout = QHBoxLayout()
        password_strength_layout.addWidget(QLabel('Password Strength:'))
        self.password_strength = QProgressBar()
        self.password_strength.setRange(0, 100)
        self.password_strength.setValue(0)
        self.password_strength.setTextVisible(False)
        self.password_strength.setStyleSheet("""
            QProgressBar {
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                background-color: #f2f2f2;
                height: 10px;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                                stop:0 #e76f51, stop:0.5 #f4a261, stop:1 #2a9d8f);
            }
        """)
        self.password_input.textChanged.connect(self.update_password_strength)
        password_strength_layout.addWidget(self.password_strength)
        card_layout.addLayout(password_strength_layout)
        
        # Options
        options_layout = QVBoxLayout()
        
        # Backup option
        self.backup_checkbox = QCheckBox("Create backup before modifying file")
        self.backup_checkbox.setChecked(True)
        options_layout.addWidget(self.backup_checkbox)
        
        card_layout.addLayout(options_layout)
        
        # Action buttons row
        action_layout = QHBoxLayout()
        self.encrypt_button = StyledButton('Encrypt', primary=True)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button = StyledButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt_file)
        action_layout.addWidget(self.encrypt_button)
        action_layout.addWidget(self.decrypt_button)
        card_layout.addLayout(action_layout)
        
        # Status label
        self.status_label = QLabel('')
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        self.status_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.status_label)
        
        # Add card to main layout
        main_layout.addWidget(card)
    
    def validate_passwords(self):
        """Check if passwords match and update the UI accordingly"""
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if not confirm_password:
            self.password_match_label.setText("")
            return
            
        if password == confirm_password:
            self.password_match_label.setText("✅ Passwords match")
            self.password_match_label.setStyleSheet("color: #2a9d8f;")
        else:
            self.password_match_label.setText("❌ Passwords don't match")
            self.password_match_label.setStyleSheet("color: #e76f51;")
        
    def update_password_strength(self, password):
        # Simple password strength calculation
        strength = 0
        if len(password) > 0:
            strength += 20
        if len(password) > 7:
            strength += 20
        if any(c.islower() for c in password):
            strength += 20
        if any(c.isupper() for c in password):
            strength += 20
        if any(c.isdigit() for c in password) or any(not c.isalnum() for c in password):
            strength += 20
            
        self.password_strength.setValue(strength)
        
        # Update progress bar color based on strength
        if strength < 40:
            color = "#e76f51"  # red
        elif strength < 70:
            color = "#f4a261"  # orange
        else:
            color = "#2a9d8f"  # green
            
        self.password_strength.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                background-color: #f2f2f2;
                height: 10px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if file_path:
            self.selected_file_path = file_path
            self.file_label.setText(os.path.basename(file_path))
            self.status_label.setText(f"Ready to process {os.path.basename(file_path)}")
            
            # Try to detect if file is encrypted
            self.detect_encryption_status()
    
    def detect_encryption_status(self):
        """Try to determine if the selected file is encrypted"""
        if not self.selected_file_path:
            return
            
        try:
            with open(self.selected_file_path, 'rb') as file:
                data = file.read(32)  # Read enough bytes to check format
                
            # Check if this looks like our encrypted format (16-byte salt + Fernet data)
            # Fernet data usually starts with 'gAAAAA' after the 16-byte salt
            if len(data) >= 22 and data[16:22] == b'gAAAAA':
                self.is_file_encrypted = True
                self.file_status.setText("File appears to be encrypted")
                self.file_status.setStyleSheet("color: #2a9d8f; font-weight: bold;")
            else:
                self.is_file_encrypted = False
                self.file_status.setText("File appears to be unencrypted")
                self.file_status.setStyleSheet("color: #666; font-style: italic;")
        except Exception as e:
            self.file_status.setText(f"Unable to determine file status: {str(e)}")
            self.file_status.setStyleSheet("color: #666; font-style: italic;")
    
    def create_backup(self, file_path):
        """Create a backup of the file before modifying it"""
        if not os.path.exists(file_path):
            return False
            
        backup_path = file_path + ".backup"
        try:
            with open(file_path, 'rb') as src_file:
                with open(backup_path, 'wb') as backup_file:
                    backup_file.write(src_file.read())
            return backup_path
        except Exception:
            return False
        
    def encrypt_file(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, 'Warning', 'Please select a file first.')
            return
            
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if not password:
            QMessageBox.warning(self, 'Warning', 'Please enter a password.')
            return
            
        if password != confirm_password:
            QMessageBox.warning(self, 'Warning', 'Passwords do not match.')
            return
            
        # Check if the file is already encrypted
        if self.is_file_encrypted:
            response = QMessageBox.question(self, 'File Already Encrypted',
                                           'This file appears to already be encrypted. Are you sure you want to encrypt it again?',
                                           QMessageBox.Yes | QMessageBox.No)
            if response == QMessageBox.No:
                return
                
        # Create backup if requested
        backup_path = None
        if self.backup_checkbox.isChecked():
            backup_path = self.create_backup(self.selected_file_path)
            
        try:
            # Generate a random salt
            salt = os.urandom(16)
            
            # Generate key from password with the random salt
            password = password.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Create a Fernet cipher with the key
            cipher = Fernet(key)
            
            # Read the file content
            with open(self.selected_file_path, 'rb') as file:
                file_data = file.read()
                
            # Encrypt the data
            encrypted_data = cipher.encrypt(file_data)
            
            # Prepend the salt to the encrypted data
            final_data = salt + encrypted_data
            
            # Write the encrypted data back to the same file
            with open(self.selected_file_path, 'wb') as file:
                file.write(final_data)
                
            self.status_label.setText(f"✅ File encrypted successfully!")
            if backup_path:
                self.status_label.setText(f"✅ File encrypted successfully! Backup created at: {os.path.basename(backup_path)}")
                
            self.status_label.setStyleSheet("color: #2a9d8f; font-weight: bold;")
            self.is_file_encrypted = True
            self.file_status.setText("File is encrypted")
            self.file_status.setStyleSheet("color: #2a9d8f; font-weight: bold;")
            
        except Exception as e:
            self.status_label.setText(f"❌ Encryption failed: {str(e)}")
            self.status_label.setStyleSheet("color: #e76f51; font-weight: bold;")
            
    def decrypt_file(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, 'Warning', 'Please select a file first.')
            return
            
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, 'Warning', 'Please enter a password.')
            return
            
        # Check if the file is encrypted
        if not self.is_file_encrypted:
            response = QMessageBox.question(self, 'File May Not Be Encrypted',
                                          'This file does not appear to be encrypted. Attempting to decrypt it may cause data corruption. Continue anyway?',
                                          QMessageBox.Yes | QMessageBox.No)
            if response == QMessageBox.No:
                return
                
        # Create backup if requested
        backup_path = None
        if self.backup_checkbox.isChecked():
            backup_path = self.create_backup(self.selected_file_path)
            
        try:
            # Read the encrypted file content
            with open(self.selected_file_path, 'rb') as file:
                file_data = file.read()
                
            # Validate minimum file size
            if len(file_data) < 16:
                raise ValueError("File too small to be a valid encrypted file")
                
            # Extract the salt (first 16 bytes)
            salt = file_data[:16]
            encrypted_data = file_data[16:]
            
            # Validate encrypted data format
            if not encrypted_data.startswith(b'gAAAAA'):
                raise ValueError("Invalid encryption format. File may be corrupted or not encrypted with this tool.")
            
            # Generate key from password with the extracted salt
            password = password.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Create a Fernet cipher with the key
            cipher = Fernet(key)
            
            # Decrypt the data
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except Exception as e:
                # Handle decryption failure (likely wrong password)
                raise ValueError(f"Decryption failed - is the password correct? Error: {str(e)}")
            
            # Write the decrypted data back to the same file
            with open(self.selected_file_path, 'wb') as file:
                file.write(decrypted_data)
                
            self.status_label.setText(f"✅ File decrypted successfully!")
            if backup_path:
                self.status_label.setText(f"✅ File decrypted successfully! Backup created at: {os.path.basename(backup_path)}")
                
            self.status_label.setStyleSheet("color: #2a9d8f; font-weight: bold;")
            self.is_file_encrypted = False
            self.file_status.setText("File is decrypted")
            self.file_status.setStyleSheet("color: #666; font-style: italic;")
            
        except ValueError as e:
            self.status_label.setText(f"❌ {str(e)}")
            self.status_label.setStyleSheet("color: #e76f51; font-weight: bold;")
            # If we have a backup, suggest restoring it
            if backup_path:
                restore = QMessageBox.question(self, 'Decryption Failed',
                                             f'Decryption failed: {str(e)}\n\nWould you like to restore the file from backup?',
                                             QMessageBox.Yes | QMessageBox.No)
                if restore == QMessageBox.Yes:
                    try:
                        with open(backup_path, 'rb') as backup_file:
                            with open(self.selected_file_path, 'wb') as target_file:
                                target_file.write(backup_file.read())
                        self.status_label.setText(f"✅ Original file restored from backup")
                        self.status_label.setStyleSheet("color: #2a9d8f; font-weight: bold;")
                    except Exception as restore_error:
                        self.status_label.setText(f"❌ Failed to restore backup: {str(restore_error)}")
        except Exception as e:
            self.status_label.setText(f"❌ Decryption failed: {str(e)}")
            self.status_label.setStyleSheet("color: #e76f51; font-weight: bold;")
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptorApp()
    window.show()
    sys.exit(app.exec_())