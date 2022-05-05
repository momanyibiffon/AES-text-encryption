from Crypto.Cipher import AES
from secrets import token_bytes # for random key generator

key = token_bytes(16)

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag


def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    # checking if the message was manipulated or not

    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = decrypt(input('Enter a message: \n'))
plaintext = decrypt(nonce, ciphertext, tag)

if not plaintext:
    print("Message is currupted!")
else:
    print(f'Pliantext: {plaintext}')





