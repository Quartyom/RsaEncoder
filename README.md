# RsaEncoder
This script helps you to encode and decode messages for transmission over unsecured communication channels. You can exchange public keys with your interlocutor, so the app will encode your messages and decode person's messages. Do not share private keys. Remember about [Man-in-the-middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
# How to use it
Install cryptography package with 
```
pip install cryptography
```
Run main.py. Enter a chat name. Use one chat name for one interlocutor, so each chat will be secured with different keys.
For the first time the script will generate keys for you. Replace you public key with your interlocutor's public key and ask them to do the same. Rerun script.
You can run script twice for convenience (for encryption and decryption).
