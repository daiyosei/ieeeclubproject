# Secure Messenger — Encryption Demo

## Generative AI was heavily used for making this project

A small, local-only KivyMD app for learning how **hybrid encryption** works. It
uses AES-GCM to encrypt message text and RSA-OAEP to protect the AES key. The
“sender” and “receiver” are roles in the same app: this project does **not** send
messages over a network.

> **Educational demo, not a production messenger.** Read [Security limits](#security-limits)
> before using it with real or sensitive data.

## What the encryption demonstrates

RSA is useful for protecting a small secret, but is inefficient for encrypting a
whole message. AES is designed to encrypt data efficiently, so this app combines
the two:

1. **Generate a fresh AES-256 key** (32 random bytes) for each message.
2. **Encrypt the message with AES-256-GCM.** GCM also creates an authentication
   tag, which lets decryption detect changes to the encrypted data. A fresh,
   random 12-byte nonce is generated for the operation.
3. **Wrap the AES key with RSA-2048-OAEP using SHA-256** and the recipient's
   public key. Only the matching private key can unwrap it.
4. Store the wrapped key, nonce, and ciphertext as Base64 text in a JSON file.
   Base64 is just an encoding for storing binary data; it is not encryption.

The flow is:

```text
Message ──AES-256-GCM + random AES key──> Ciphertext + authentication tag
                                               │
Random AES key ──RSA-OAEP + public key──> Wrapped AES key
                                               │
                              JSON: wrapped key, nonce, ciphertext
```

To decrypt, the app uses the private key to unwrap the AES key, then uses that
key and the saved nonce to decrypt and authenticate the message. If the bundle
was altered or the wrong key is used, authentication/decryption fails.

### What is in a saved message?

Each JSON bundle has three fields:

| Field | Purpose |
| --- | --- |
| `wrapped_key` | AES key encrypted with RSA-OAEP and Base64-encoded |
| `nonce` | AES-GCM nonce, Base64-encoded; it is not secret |
| `ciphertext` | Encrypted message and GCM authentication tag, Base64-encoded |

The nonce and wrapped key must be stored with the ciphertext so the intended
private key can decrypt and authenticate it. The plaintext is not stored in the
encrypted message file.

## Try the demo

### Install and run

Use a Python environment supported by Kivy and install the listed dependencies:

```bash
python -m pip install -r requirements.txt
python main.py
```

### Encrypt and decrypt

1. Click **Generate RSA Key Pair** to create a 2048-bit RSA pair.
2. Enter a message and click **Encrypt (Sender)**. The result area shows the
   encoded encrypted bundle, not the plaintext.
3. Click **Decrypt (Receiver)** to decrypt the current bundle with the private
   key. The recovered text is shown and placed back in the message field.
4. Optionally use **Save Message to File** and **Load Message from File** to
   persist or reopen the encrypted JSON bundle. Loading a bundle does not decrypt
   it automatically.

To reuse a key pair after restarting the app, click **Save Keys** before
restarting, then **Load Keys**. Keys are stored in `keys/public_key.pem` and
`keys/private_key.pem` relative to the app's working directory. Encrypted
messages are saved wherever selected in the file dialog.

## Security limits

This app illustrates cryptographic building blocks; it does not implement a
complete secure messaging protocol.

- **No networking or key exchange:** “sending” and “receiving” happen locally.
  The app does not establish a connection or securely distribute public keys.
- **No sender authentication or signatures:** RSA-OAEP encryption does not prove
  who created a message. Anyone with the recipient's public key can create a
  bundle for them. AES-GCM detects tampering, but is not a digital signature.
- **Private keys are saved unencrypted:** `private_key.pem` is written as PEM
  with no passphrase. Anyone who can read that file may decrypt saved bundles
  encrypted to its matching public key. Protect or remove the key files
  appropriately.
- **No forward secrecy:** Saved bundles rely on the RSA private key remaining
  secret. A later compromise of that key can expose bundles encrypted to it.
- **No identity verification:** The demo does not verify that a loaded public
  key really belongs to the intended recipient.

Do not use this demo to protect real confidential information. A production
messenger needs a reviewed protocol, authenticated key distribution, protected
key storage, and careful operational security in addition to sound algorithms.

## Project files

- `main.py` / `main.kv` — KivyMD interface and actions.
- `crypto_utils.py` — RSA, AES-GCM, encoding, and encrypted-file helpers.
- `file_dialogs.py` — local file selection dialogs.
- `requirements.txt` — Python package dependencies.
