# This is a proof-of-concept for a timing attack against an AES/CBC encryption scheme
# using a MAC-then-encrypt scheme for integrity. This attack manages to successfully
# decrypt the first byte of each 16-byte block.
# Adapted from https://gist.github.com/defuse/0822a9c6d70ab4939c95

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto import Random

# Note: all the blocks here are 16-bytes

# We encrypt using AES in CBC mode and a MAC-then-Encrypt scheme
# If Enc() is the AES encryption function with the secret key
# and Decr() the AES decryption function with the secret key
# the encrypt() function returns:
# IV | Enc/CBC(plaintext | MAC)
def encrypt(plaintext, key):
	# Generate a 128-bit key out of a text key
	h = HMAC.new(b'Key generation')
	h.update(bytes(key + ' this is a salt', 'ascii'))
	aes_key = h.digest()

	# Generate a random IV
	iv = Random.new().read(AES.block_size)

	# Generate the MAC for the plaintext
	h = HMAC.new(aes_key)
	h.update(bytes(plaintext, 'ascii'))
	mac = h.digest()

	# Encrypt plaintext | MAC
	cipher = AES.new(aes_key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(bytes(plaintext, 'ascii') + mac)

	return iv + ciphertext

# For the decryption
def decrypt(enc_message, key):
	h = HMAC.new(b'Key generation')
	h.update(bytes(key + ' this is a salt', 'ascii'))
	aes_key = h.digest()

	# Get the IV from the message
	iv = enc_message[0:16]
	cipher = AES.new(aes_key, AES.MODE_CBC, iv)
	decr_message = cipher.decrypt(enc_message[16:])
	mac = decr_message[-16:]
	plaintext = decr_message[:-16]

	# Compute the MAC
	h = HMAC.new(aes_key)
	h.update(plaintext)
	computed_mac = h.digest()

	# If the computed MAC equals the ciphertext MAC, return the plaintext
	if computed_mac == mac:
		return plaintext

	# Simulates the timing attack
	# If the two MACs differ but share the same first byte
	# return 1
	return 1 if computed_mac[0] == mac[0] else 0


##################################################
# STEP #1: Get the ciphertext
##################################################
secret_key = 'This is a secret key'
message = 'This is the secret message that is supposed to be confidential. In practice, some info can leak!'
ciphertext = encrypt(message, secret_key)
# We split the ciphertext into blocks.
# We keep the IV (first 16 bytes) but strip the MAC (last 16 bytes)
ct_blocks = [ ciphertext[idx:idx+16] for idx in range(0, len(ciphertext)-16, 16) ]

# We decrypt the message for testing purposes only
# We print the plaintext in 16-bytes blocks to better
# verify the first character
plaintext = decrypt(ciphertext, secret_key).decode('ascii')

print('Plaintext blocks:')
for idx in range(0, len(plaintext), 16):
	print('[%s]' % plaintext[idx:idx+16])


##################################################
# STEP #2: Conduct the Chosen-Plaintext Attack
##################################################
# We build a dictionary (Key, Value) where
# Decr(Value)[0] = Key
# for all values of Key between 0...255
CPA_dict = {}
# Generate a known plaintext
plaintext = 'a'*16

# We stop when all 256 values are filled
while len(CPA_dict) < 256:
	# We encrypt just one block, so the message should be 3 blocks:
	# IV | ciphertext | MAC
	message= encrypt(plaintext, secret_key)
	iv = message[0:16]
	ciphertext = message[16:-16]

	# plaintext = Decr(ciphertext) XOR iv
	# => Decr(ciphertext) = plaintext XOR iv
	# => Decr(ciphertext)[0] = plaintext[0] XOR iv[0]
	decrypted_byte = ord('a') ^ iv[0]
	CPA_dict[decrypted_byte] = ciphertext


##################################################
# STEP #3: Conduct the Chosen-Ciphertext Attack
##################################################
print()
print('Information leaked:')

# Generate a zero-filled IV
iv = bytes(chr(0)*16, 'ascii')

# We go through all the blocks but the first one (which is the IV)
for idx in range(1, len(ct_blocks)):
	# Generate a random ciphertext
	rand = Random.new().read(AES.block_size)

	# We send a 3-block message to the decrypt function
	# and repeat with a new rand until we get a collision
	message = iv + rand + ct_blocks[idx]
	while decrypt(message, secret_key) != 1:
		rand = Random.new().read(AES.block_size)
		message = iv + rand + ct_blocks[idx]

	# The loop ends when:
	# MAC(Decr(rand))[0] = Decr(ct_blocks[idx])[0]

	# We now go through all the possible first bytes
	for nb in range(0, 256):
		message = iv + rand + CPA_dict[nb]
		# If we have a collision
		if decrypt(message, secret_key)	== 1:
			# MAC(Decr(rand))[0] = Decr(ct_blocks[idx])[0] (see line 132)
			# MAC(Decr(rand))[0] = Decr(CPA_dict[nb])[0] = nb (per CPA_dict property, see line 89)
			# => Decr(ct_blocks[idx])[0] = nb

			# In CBC mode, pt_blocks[idx] = Decr(ct_blocks[idx]) XOR ct_blocks[idx-1]
			# (if pt_blocks is the plaintext counterpart of ct_blocks)
			# => pt_blocks[idx][0] = Decr(ct_blocks[idx])[0] XOR ct_blocks[idx-1][0]
			# => pt_blocks[idx][0] = nb XOR ct_blocks[idx-1][0]
			decrypted_byte = nb ^ ct_blocks[idx-1][0]
			print('Block #%d = [%s...]' % (idx, chr(decrypted_byte)) )
