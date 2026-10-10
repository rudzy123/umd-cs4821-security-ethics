# Cryptography basics

This note draws the lines the lab's code is built to keep visible. The implementations live in `src/secure_notes/crypto_lab.py` and `src/secure_notes/passwords.py`. Both call maintained libraries. Neither file implements a cipher, a hash function, or a signature scheme.

## Five operations people mix up

| Operation | Key? | Hides the message? | Detects modification? | Who can check it? |
| --- | --- | --- | --- | --- |
| Encoding (base64) | No | No | No | Anyone |
| Cryptographic hash | No | Not a substitute for encryption | Only if you already have a trusted copy of the digest | Anyone, by recomputing it |
| Salted hash | Salt is not a secret | Same limit as a hash | Same limit as a hash | Anyone who has the salt and the digest |
| MAC (HMAC) | Shared secret | No | Yes | Anyone with the same secret |
| Authenticated encryption (AES-256-GCM) | Shared secret | Yes | Yes | Anyone with the same secret |
| Digital signature (Ed25519) | Private key signs, public key verifies | No | Yes | Anyone with the public key |

If you need a property from a different row, use the operation on that row. Stacking base64 on a password does not move you down the table.

## Encoding

`encode_base64` changes the alphabet so bytes survive in a JSON string or a header. `decode_base64` reverses it with no key. A ciphertext that has been base64-encoded is still ciphertext. Decoding it does not decrypt it. The lab test `test_hash_encoding_and_salt_are_different_ideas` checks that a decoded token is not the plaintext.

## Cryptographic hashing

`cryptographic_hash` returns SHA-256 of the input. The same input always produces the same 32-byte digest. The digest is not a compressed copy of the message: the original is not sitting inside it, and the function has no inverse in this package.

A hash does not authenticate a message by itself. Anyone can hash a replacement message. A hash is useful when you compare it to a digest that arrived through a channel you already trust, or when it is a building block inside HMAC or a signature.

SHA-256 is also the wrong tool for storing a password. It is fast, which is what a guessing attack wants.

## Salts

`demonstrate_salt` computes SHA-256 over a length byte, a salt, and the message. A salt is random, and it is stored next to the digest. It is not a key. Its job is to make two equal inputs produce different digests so a precomputed table has to be rebuilt per salt.

That demonstration is not a password store. It has none of the memory hardness password guessing needs. The notes API stores passwords with Argon2id (`hash_password`). Argon2id generates its own salt and stores it inside the hash string. You do not invent a second salt beside it. Two registrations with the same password produce two different stored strings; `tests/test_passwords.py` and `tests/test_auth.py` both check that.

## HMAC

`compute_hmac` and `verify_hmac` use HMAC-SHA256 from the `cryptography` package. The tag depends on a 32-byte key drawn from `secrets`. The message can sit beside the tag in the clear. Verification answers "did someone who knows the key produce this tag for this exact message?"

`verify_hmac` uses the library's compare and returns false on a mismatch. The tests change the message, flip a tag byte, and use a second key. All three must fail. Equal inputs and the same key produce the same tag: a MAC is not randomized encryption.

The API also uses HMAC, through the standard-library `hmac` module, for a different purpose. `hash_bearer_token` computes HMAC-SHA256 of the bearer token under `NOTES_SECRET_KEY` and stores the hex digest. The raw token is what the client retries. A copy of the database does not contain that token. This is an identifier, not encryption of the session.

## Authenticated encryption

`encrypt_aes_gcm` draws a 96-bit nonce with `secrets`, encrypts with AES-256-GCM, and returns `nonce || ciphertext || tag`. The key is 32 random bytes from `generate_aes_key`. A password string is not an AES key. Turning a password into a key would be a separate slow derivation step, and this lab does not need one because the lab keys are already random.

AES-GCM fails closed when the ciphertext, the tag, the nonce, or the associated data changes. Associated data is covered by the tag and is not hidden. The lab uses that for a context string such as a note id: the same ciphertext cannot be silently moved to a different context. `decrypt_aes_gcm` raises `IntegrityCheckFailed` with a fixed message so the exception text cannot contain the plaintext or the key.

Two encryptions of the same plaintext produce different tokens because the nonce is random. That is the opposite of raw SHA-256, and the tests check both facts.

The notes table does **not** call this function. Applying GCM to notes would be a small code change and a large key-management problem: where the key lives, who can read it, and how it rotates. The threat model records plaintext notes as residual risk rather than half-implementing that design.

## Digital signatures

`generate_signing_key` asks the library for an Ed25519 private key. `sign_message` signs with the private key. `verify_signature` checks with the public key. A valid signature says the holder of the private key signed that exact message. It does not hide the message. Anyone with the public key can verify, which is the point: verification does not require the secret.

The tests flip a message byte and a signature byte. Verification returns false. There is no "repair" path.

Do not use a signature where you needed encryption, and do not use a MAC where you needed a public verifier. A MAC forces the verifier to hold the same secret, so a verifier can also forge. A signature does not give the verifier that power.

## Random tokens

`generate_secret_token` calls `secrets.token_urlsafe` and refuses fewer than 32 bytes of entropy. That function is the right source for bearer tokens, reset codes, and keys. The `random` module is not used in this package. Tokens are compared by storing an HMAC and looking it up, not by inventing a comparison loop.

A token is not a password. It is not memorable, and it is not entered by a person. It is also not a hash of the user's password.

## Choices this lab refuses

* Implementing AES, SHA-256, HMAC, Argon2, or Ed25519 in course code.
* Storing passwords with SHA-256, even with the demonstration salt.
* Using ECB, or a stream cipher with a reused nonce. The lab does not expose those modes at all.
* Treating a passed verification as optional. Tampered input is a failure, not a warning.
* Logging a key, a token, a password, or a plaintext in an exception message.

## Where to read next

* Password storage and generic login errors: `src/secure_notes/passwords.py` and `docs/security-principles.md`
* What is encrypted and what is not: `docs/threat-model.md`
* How a failure should be reported if you find one in this lab: `docs/responsible-disclosure.md`
