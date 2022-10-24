import sys
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from encrypt import generate_key
# from encrypt import generate_key



def main():
    if len(sys.argv) < 3:
        print("Usage: python3 decrypt.py <input_file> <output_file>")
        exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    

    with open(input_file, 'rb') as input_file:
        iv = input_file.read(16)
        salt = input_file.read(16)
        data = input_file.read()

    password = input("Insert the password to transform into a key: ")
    key = generate_key(password, "AES-128", salt)

    decrypted_data = decrypt(data, key, iv)
    unpadded_data = unpadder(decrypted_data) 

    with open(output_file, 'wb') as output_file:
        output_file.write(unpadded_data)

def unpadder(decrypted_data):
    padder = padding.PKCS7(128).padder()
    
    return padder.update(decrypted_data) + padder.finalize()
   

def decrypt(data, key, iv):   
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data


if __name__ == '__main__':
    main()