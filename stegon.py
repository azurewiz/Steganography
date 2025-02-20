import cv2
import numpy as np

#######################################
# Utility Functions
#######################################

def text_to_bits(text):
    """Convert a string into its binary representation (bits)."""
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    """Convert a binary string back to text (8 bits per character)."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def bytes_to_bits(b):
    """Convert a bytes-like object into a binary string."""
    return ''.join(format(byte, '08b') for byte in b)

def bits_to_bytes(bitstring):
    """Convert a binary string to a bytes object."""
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
    Embed a string of bits into the LSB of the image pixels.
    img should be a NumPy array (H x W x 3).
    data_bits is a string of '0' and '1'.
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
    bits = []
    for i in range(num_bits):
        bits.append(str(flat_img[i] & 1))
    return ''.join(bits)

def encrypt_message(cover_path, secret_message, passcode):
    """
    Embed (encrypt) a secret message into a cover image.
    Saves the resulting image as 'encryptedImage.png'.
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
    length_bits = format(length, '032b')  # 32-bit representation
    
    # Combine length bits and encrypted bits
    final_bits = length_bits + encrypted_bits
    mod_img = embed_data_lsb(img, final_bits)
    
    # Save as PNG (lossless format)
    cv2.imwrite("encryptedImage.png", mod_img)
    print("Message encrypted and saved as 'encryptedImage.png'.")

def decrypt_message(encrypted_path, passcode):
    """
    Extract and decrypt a hidden message from an image.
    Returns the decrypted message as a string.
    """
    # Load the encrypted image
    img = cv2.imread(encrypted_path)
    if img is None:
        raise ValueError("Could not load encrypted image!")
    
    # Extract the 32 bits that store the message length
    length_bits = extract_data_lsb(img, 32)
    length = int(length_bits, 2)
    
    # Extract the encrypted message bits
    full_bits = extract_data_lsb(img, 32 + length)
    enc_data_bits = full_bits[32:]  # skip the length bits
    enc_data_bytes = bits_to_bytes(enc_data_bits)
    
    # XOR-decrypt the data
    dec_bytes = xor_decrypt_bytes(enc_data_bytes, passcode)
    message = dec_bytes.decode('utf-8', errors='replace')
    return message

#######################################
# Command-Line Interface
#######################################

def main():
    print("Welcome to the Image Steganography CLI Program")
    print("Select an option:")
    print("1. Encrypt a message into an image")
    print("2. Decrypt a message from an image")
    
    choice = input("Enter 1 or 2: ").strip()
    
    if choice == "1":
        cover_path = input("Enter the path to the cover image (png, jpg, bmp, etc.): ").strip()
        secret_message = input("Enter the secret message: ")
        passcode = input("Enter a passcode: ")
        try:
            encrypt_message(cover_path, secret_message, passcode)
        except Exception as e:
            print("Error during encryption:", e)
    
    elif choice == "2":
        encrypted_path = input("Enter the path to the encrypted image (png): ").strip()
        passcode = input("Enter the passcode: ")
        try:
            message = decrypt_message(encrypted_path, passcode)
            print("\nDecrypted message:")
            print(message)
        except Exception as e:
            print("Error during decryption:", e)
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
