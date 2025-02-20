import sys
import cv2
import numpy as np
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt

#######################################
# Utility Functions
#######################################

def text_to_bits(text):
    """Convert a string into its binary representation (8 bits per character)."""
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    """Convert a binary string (multiple of 8 bits) back to text."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def bytes_to_bits(b):
    """Convert a bytes-like object into a binary string."""
    return ''.join(format(byte, '08b') for byte in b)

def bits_to_bytes(bitstring):
    """Convert a binary string (multiple of 8 bits) into a bytes object."""
    return bytes(int(bitstring[i:i+8], 2) for i in range(0, len(bitstring), 8))

def xor_encrypt_decrypt(message_str, passcode_str):
    """
    XOR-based 'encryption' of a string with a passcode.
    Returns a bytearray of the encrypted data.
    """
    msg_bytes = message_str.encode('utf-8')
    key_bytes = passcode_str.encode('utf-8')
    out_bytes = bytearray()
    for i in range(len(msg_bytes)):
        out_bytes.append(msg_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return out_bytes

def xor_decrypt_bytes(enc_bytes, passcode_str):
    """
    XOR-based 'decryption' of a bytes-like object with a passcode.
    Returns the decrypted bytes.
    """
    key_bytes = passcode_str.encode('utf-8')
    out_bytes = bytearray()
    for i in range(len(enc_bytes)):
        out_bytes.append(enc_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return out_bytes

#######################################
# Steganography Core Functions
#######################################

def embed_data_lsb(img, data_bits):
    """
    Embed a string of bits into the least significant bit of the image pixels.
    img is a NumPy array (H x W x 3); data_bits is a string of '0' and '1'.
    """
    h, w, c = img.shape
    total_values = h * w * c
    if len(data_bits) > total_values:
        raise ValueError("Not enough space in image to embed data!")
    flat_img = img.flatten()
    for i in range(len(data_bits)):
        flat_img[i] = (flat_img[i] & 0xFE) | int(data_bits[i])
    mod_img = flat_img.reshape(h, w, c)
    return mod_img

def extract_data_lsb(img, num_bits):
    """
    Extract num_bits from the LSB of the image pixels.
    Returns a string of '0' and '1'.
    """
    flat_img = img.flatten()
    bits = [str(flat_img[i] & 1) for i in range(num_bits)]
    return ''.join(bits)

def encrypt_message(cover_path, secret_message, passcode):
    """
    Embed (encrypt) a secret message into a cover image.
    Saves the output image as 'encryptedImage.png'.
    """
    # Load the cover image
    img = cv2.imread(cover_path)
    if img is None:
        raise ValueError("Could not load cover image!")
    
    # XOR-encrypt the message
    encrypted_bytes = xor_encrypt_decrypt(secret_message, passcode)
    encrypted_bits = bytes_to_bits(encrypted_bytes)
    
    # Store the length of the encrypted data (in bits) in the first 32 bits
    length = len(encrypted_bits)
    if length > (2**32 - 1):
        raise ValueError("Message too large to store length in 32 bits!")
    length_bits = format(length, '032b')
    
    # Combine length bits and encrypted bits
    final_bits = length_bits + encrypted_bits
    mod_img = embed_data_lsb(img, final_bits)
    
    # Save the result as PNG (lossless)
    cv2.imwrite("encryptedImage.png", mod_img)

def decrypt_message(encrypted_path, passcode):
    """
    Extract and decrypt a hidden message from an image.
    Returns the decrypted message as a string.
    """
    img = cv2.imread(encrypted_path)
    if img is None:
        raise ValueError("Could not load encrypted image!")
    
    # Extract the first 32 bits that store the length
    length_bits = extract_data_lsb(img, 32)
    length = int(length_bits, 2)
    
    # Extract the encrypted message bits
    full_bits = extract_data_lsb(img, 32 + length)
    enc_data_bits = full_bits[32:]
    enc_data_bytes = bits_to_bytes(enc_data_bits)
    
    # XOR-decrypt to recover the message
    dec_bytes = xor_decrypt_bytes(enc_data_bytes, passcode)
    message = dec_bytes.decode('utf-8', errors='replace')
    return message

#######################################
# PyQt5 GUI Classes
#######################################

class StegoWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Image Steganography (LSB + XOR)")
        self.resize(600, 400)
        
        # Create a tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create two tabs: Encryption and Decryption
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        self.tabs.addTab(self.encrypt_tab, "Encryption")
        self.tabs.addTab(self.decrypt_tab, "Decryption")
        
        self.init_encrypt_tab()
        self.init_decrypt_tab()
    
    def init_encrypt_tab(self):
        layout = QVBoxLayout()
        
        # Cover Image Selection
        h_layout1 = QHBoxLayout()
        self.cover_label = QLabel("Cover Image:")
        self.cover_line = QLineEdit()
        self.cover_line.setReadOnly(True)
        self.cover_browse = QPushButton("Browse")
        self.cover_browse.clicked.connect(self.browse_cover_image)
        h_layout1.addWidget(self.cover_label)
        h_layout1.addWidget(self.cover_line)
        h_layout1.addWidget(self.cover_browse)
        layout.addLayout(h_layout1)
        
        # Secret Message Input
        h_layout2 = QHBoxLayout()
        label_msg = QLabel("Secret Message:")
        self.message_edit = QLineEdit()
        h_layout2.addWidget(label_msg)
        h_layout2.addWidget(self.message_edit)
        layout.addLayout(h_layout2)
        
        # Passcode Input
        h_layout3 = QHBoxLayout()
        label_pass = QLabel("Passcode:")
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        h_layout3.addWidget(label_pass)
        h_layout3.addWidget(self.pass_edit)
        layout.addLayout(h_layout3)
        
        # Encrypt Button
        self.encrypt_btn = QPushButton("Encrypt and Save")
        self.encrypt_btn.clicked.connect(self.handle_encrypt)
        layout.addWidget(self.encrypt_btn)
        
        self.encrypt_status = QLabel("")
        layout.addWidget(self.encrypt_status)
        
        self.encrypt_tab.setLayout(layout)
    
    def init_decrypt_tab(self):
        layout = QVBoxLayout()
        
        # Encrypted Image Selection
        h_layout1 = QHBoxLayout()
        self.enc_image_label = QLabel("Encrypted Image:")
        self.enc_image_line = QLineEdit()
        self.enc_image_line.setReadOnly(True)
        self.enc_image_browse = QPushButton("Browse")
        self.enc_image_browse.clicked.connect(self.browse_encrypted_image)
        h_layout1.addWidget(self.enc_image_label)
        h_layout1.addWidget(self.enc_image_line)
        h_layout1.addWidget(self.enc_image_browse)
        layout.addLayout(h_layout1)
        
        # Passcode Input for Decryption
        h_layout2 = QHBoxLayout()
        label_dec_pass = QLabel("Passcode:")
        self.dec_pass_edit = QLineEdit()
        self.dec_pass_edit.setEchoMode(QLineEdit.Password)
        h_layout2.addWidget(label_dec_pass)
        h_layout2.addWidget(self.dec_pass_edit)
        layout.addLayout(h_layout2)
        
        # Decrypt Button
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.handle_decrypt)
        layout.addWidget(self.decrypt_btn)
        
        # Text area for displaying decrypted message
        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        layout.addWidget(self.decrypted_text)
        
        self.decrypt_tab.setLayout(layout)
    
    def browse_cover_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp)"
        )
        if path:
            self.cover_line.setText(path)
    
    def browse_encrypted_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Encrypted Image", "", "PNG Files (*.png);;All Files (*)"
        )
        if path:
            self.enc_image_line.setText(path)
    
    def handle_encrypt(self):
        cover_path = self.cover_line.text().strip()
        secret_message = self.message_edit.text()
        passcode = self.pass_edit.text()
        
        if not cover_path:
            QMessageBox.warning(self, "Error", "Please select a cover image.")
            return
        if not secret_message:
            QMessageBox.warning(self, "Error", "Please enter a secret message.")
            return
        if not passcode:
            QMessageBox.warning(self, "Error", "Please enter a passcode.")
            return
        
        try:
            encrypt_message(cover_path, secret_message, passcode)
            QMessageBox.information(self, "Success", "Message encrypted and saved as 'encryptedImage.png'.")
            self.encrypt_status.setText("Encryption successful.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def handle_decrypt(self):
        encrypted_path = self.enc_image_line.text().strip()
        passcode = self.dec_pass_edit.text()
        
        if not encrypted_path:
            QMessageBox.warning(self, "Error", "Please select an encrypted image.")
            return
        if not passcode:
            QMessageBox.warning(self, "Error", "Please enter a passcode.")
            return
        
        try:
            message = decrypt_message(encrypted_path, passcode)
            self.decrypted_text.setPlainText(message)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

#######################################
# Main Entry Point
#######################################

def main():
    app = QApplication(sys.argv)
    window = StegoWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
