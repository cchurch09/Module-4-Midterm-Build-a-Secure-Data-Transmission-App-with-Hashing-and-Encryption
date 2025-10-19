import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

#Accepts user input (e.g., a message or file)
message = input("Enter your message for excryption:  ")

#hashes the input using SHA-256 to ensure integrity
hash_original = hashlib.sha256(message.encode()).hexdigest
print(f"\nOriginal SHA-256 Hash: {hash_original}")

#Encrypts the input using symmetric encryption (e.g., AES)
key = get_random_bytes(32)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

def pad(s):
    padding_length = 16 - len(s) % 16
    return s + chr(padding_length) * padding_length

padded_message = pad(message)
ciphertext = cipher.encrypt(padded_message.encode())
encoded_ciphertext = base64.b64encode(ciphertext).decode()
print(f"\nEncrypted (Base64): {encoded_ciphertext}")

#Decrypts the content and verifies its integrity via hash comparison
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
decrypted_padded = cipher_decrypt.decrypt(ciphertext).decode()
unpadded_message = decrypted_padded[:-ord(decrypted_padded[-1])]
print(f"\nDecrypted Message: {unpadded_message}")
hash_decrypted = hashlib.sha256(unpadded_message.encode()).hexdigest()
print(f"Decrypted Message SHA-256 HASH: {hash_decrypted}")

if hash_original == hash_decrypted:
    print("\n Its a match!")
else:
    print("\n Match Fail!")

print(f"\nAES key (Base64): {base64.b64encode(key).decode()}")
print(f"Intitialization Vector (Base64): {base64.b64encode(iv).decode()}")

