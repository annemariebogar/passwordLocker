# author: Anne Marie Bogar
# last updated: December 8, 2017
# aes.py implements the AES-256 algorithm in CBC mode. 
# This program implements encryption, decryption, padding, key generation, and IV generation

from Crypto.Cipher import AES
from Crypto import Random
import base64

def gen_key():
	key = Random.new().read(32)
	return base64.b64encode(key)
	#return key

def get_key(filename):
	with open(filename, 'r') as f:
		key = f.read()
	#return base64.b64encode(key)
	return key

def gen_iv():
	iv = Random.new().read(AES.block_size)
	return iv

def aesencrypt(message, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	message = pad(message)
	return base64.b64encode(iv + cipher.encrypt(message))

def aesdecrypt(ciphertext, key):
	ciphertext = base64.b64decode(ciphertext)
	iv = ciphertext[:AES.block_size]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(ciphertext[AES.block_size:])).decode('utf-8')

def pad(message):
	return message + (AES.block_size - len(message) % AES.block_size) * chr(AES.block_size - len(message) % AES.block_size)

def unpad(message):
	return message[:-ord(message[len(message)-1:])]
