import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def main():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    pemp = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_name = input("Enter the name of the private key file: ")
    public_name = input("Enter the name of the public key file: ")

    with open(private_name, "wb") as f:
        f.write(pem_private)

    with open(public_name, "wb") as f:
        f.write(pemp)

if __name__=='__main__':
    main()
