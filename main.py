from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


def generate_keys():
    global private_key, public_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{chat_name}_public.pem", "wb") as f:
        f.write(public_key_pem)

    with open(f"{chat_name}_private.pem", "wb") as f:
        f.write(private_key_pem)

    print("Keys generated")


def encrypt(message):
    for msg in split_by_len(message, 80):
        encrypted_message = public_key.encrypt(
            msg.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(base64.b64encode(encrypted_message).decode())


def decrypt(message):
    message_bytes = base64.b64decode(message.encode())

    decrypted_message = private_key.decrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("<", decrypted_message.decode())


def split_by_len(s, l):  # "abcdefg", 3 -> "abc", "def", "g"
    out = []

    while len(s) > l:
        out.append(s[:l])
        s = s[l:]

    out.append(s)
    return out


chat_name = input("Chat name (lower case): ").lower()

try:
    with open(f"{chat_name}_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    with open(f"{chat_name}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    print("Keys loaded")
except:
    input("Keys not found. Any input to generate new")
    generate_keys()

mode = input("e for encryption, d for decryption: ")

while True:
    if mode == 'e':
        func = encrypt
        break
    elif mode == 'd':
        func = decrypt
        break
    else:
        print("Wrong choice")
        mode = input("> ")


while True:
    try:
        func(input("> "))
    except Exception as e:
        print(e)
