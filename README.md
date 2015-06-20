# Cryptography: compromising the MAC-then-encrypt scheme

This is a proof-of-concept for a timing attack against an [AES/CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) encryption scheme using a [MAC-then-encrypt](https://en.wikipedia.org/wiki/Authenticated_encryption#MAC-then-Encrypt_.28MtE.29) scheme for integrity. This attack manages to successfully decrypt the first byte of each 16-byte block. The code also shows how to decrypt the first 2 bytes of each block, but the time to perform such an operation skyrockets.

This is adapated from https://gist.github.com/defuse/0822a9c6d70ab4939c95, rewritten in Python 3 using the PyCrypto library (I rewrote it from memory to make sure I really understood the concept)

## How does it work?

This attack is combining two tricks:

- MAC Timing attack: the most obvious way to compare the MAC stored in the ciphertext with the computed MAC is to use the standard string comparison operator `==`. The downside of this approach is that the time to perform the comparison depends on the number of first bytes the two MACs have in common. An attacker able to accurately time the decrypt function can then tell if the first byte of a forged MAC is right or not (the longer the function takes, the more accurate the MAC) <sup>(*)</sup>
- With the MAC-then-encrypt scheme, the encrypt function is MAC'ing the plaintext and encrypting the concatenated (plaintext | MAC). Because both are encrypted/decyrypted using the same key, one can fool the decrypt function by passing a ciphertext block as the MAC. The decrypt function will decrypt that block and compare its plaintext.

When trying to decrypt an unknown 16-byte cipher block `CB_unknown`, if we manage to find a ciphertext `random` and a cipher block `CB_known` whose plaintext is known such as:

- Submitting `random` (ciphertext) | `CB_unknown` (encrypted MAC) => the first byte of the MAC is correct
- Submitting `random` (ciphertext) | `CB_known` (encrypted MAC) => the first byte of the MAC is correct

then we know that `CB_known` and `CB_unknown`, once decrypted, share the same first character. This allows us to know the first character for `CB_unknown`'s plaintext

## Requirements

In order for this attack to succeed, the attacker needs to be able to:

- perform a Chosen-Plaintext Attack (CPA) by encrypting as many plaintext messages as desired
- perform a Chosen-Ciphertext Attack (CCA) by submitting forged ciphertexts to an oracle to see if the decryption fails or succeeds
- precisely measure the time it takes for the decrypt function to fail, in order to see if the first byte of the MAC is correct or not

  
  

<sup>(*) Even though this is not covered here, in the case of an Encrypt-then-MAC or Encrypt-and-MAC scheme, an attacker can forge a valid MAC for a modified ciphertext. By trying all 256 possibilities for the forged MAC's first byte, the possibility that takes a bit longer to decrypt tells the MAC's correct first byte. The same operation can be repeated for the other bytes.</sup>

<sup>One way to prevent a timing attack is to make sure the comparison goes through all the characters no matter what, but beware of compiler optimizations that could short-circuit that scheme. The best protection is to hash the MACs (e.g. using SHA1) and compare the hash. Even if the comparison time varies, its timing does not give any information about the submitted MAC.</sup>
