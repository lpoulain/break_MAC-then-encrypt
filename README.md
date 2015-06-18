# Cryptography: compromising the MAC-then-encrypt scheme

This is a proof-of-concept for a timing attack against an [AES/CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) encryption scheme using a [MAC-then-encrypt](https://en.wikipedia.org/wiki/Authenticated_encryption#MAC-then-Encrypt_.28MtE.29) scheme for integrity. This attack manages to successfully decrypt the first byte of each 16-byte block.

This is adapated from https://gist.github.com/defuse/0822a9c6d70ab4939c95, rewritten in Python 3 using the PyCrypto library.

## How does it work?

This attack is combining two tricks:

- MAC Timing attack: a simple way to compare the MAC stored in the ciphertext with the computed MAC is to use the standard `==` operator. The downside of this approach is that the time to perform the comparison depends on the number of similar first bytes the two MACs have. An attacker able to accurately time the function can then tell if the first byte of a forged MAC is right or not (the longer the function takes, the more accurate the MAC). Once the first byte is determine, the same method can be applied to the second byte of the MAC, etc.
- In the MAC-the-encrypt scheme, the encrypt function is MAC'ing the plaintext and encrypting the concatenated (plaintext | MAC). Because both are encrypted/decyrypted using the same key, one can fool the decrypt function by passing a ciphertext block as the MAC. The decrypt function will decrypt that block and compare its plaintext.

## Requirements

In order for this attack to succeed, the attacker needs to be able to:

- perform a Chosen-Plaintext Attack (CPA) by encrypting as many plaintext messages as desired
- perform a Chosen-Ciphertext Attack (CCA) by submitting forged ciphertexts to an oracle to see if the decryption fails or succeeds
- precisely measure the time it takes for the decrypt function to fail, in order to see if the first byte of the MAC is correct or not
