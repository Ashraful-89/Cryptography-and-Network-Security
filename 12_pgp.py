
import zlib, secrets, base64 
from Crypto.PublicKey import RSA 
from Crypto.Hash import SHA1 
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.Random import get_random_bytes 
from Crypto.Util.Padding import pad, unpad 

def b64(data):
    s = base64.b64encode(data).decode()
    return s

# keys 
A_private = RSA.generate(2048); A_public = A_private.publickey()
B_private = RSA.generate(2048); B_public = B_private.publickey()

# sender
print("\n\nSender END\n\n")
Msg = b"How are you?"
print("\n\t[M] Original Plaintext Message: ", {Msg.decode()})

h = SHA1.new(Msg)
print("\n\t[H] Hashed Message: ", b64(h.digest()))

S = pkcs1_15.new(A_private).sign(h)
print("\n\tSign H(M) with PR_a -> signature S: ", b64(S))

signed_plain = len(S).to_bytes(2, "big") + S + Msg
print("\n\t[||] Concatenated S||M: ", b64(signed_plain))

compressed = zlib.compress(signed_plain, level=9)
print("\n\t[Z] Compressed value: ", b64(compressed))

Ks_raw = secrets.token_bytes(16)
Ks = DES3.adjust_key_parity(Ks_raw)
pt = pad(compressed, 8)
C = DES3.new(Ks, DES3.MODE_ECB).encrypt(pt)
print("\n\t[EC] Encrypted Compressed with session key: ", Ks)
print("\tCiphertext: ", b64(C))

E_Ks = PKCS1_OAEP.new(B_public).encrypt(Ks)
print("\n\t[EC] Encrypt Session Key with PU_b: ", b64(E_Ks))

packet = (E_Ks, C)
print("\n\t[||] Building transmitted packet.")

# receiver
print("\n\nReceiver END\n\n")
Ks_rec = PKCS1_OAEP.new(B_private).decrypt(packet[0])
print("\n\t[DC] Decrypted Session Key: ", Ks_rec)

pt_rec = DES3.new(Ks_rec, DES3.MODE_ECB).decrypt(packet[1])
compressed_recv = unpad(pt_rec, 8)

print("\n\t[DC] Decrypt C with Ks: ", compressed_recv)

signed_plain_recv = zlib.decompress(compressed_recv)
print(f"[Z^-1] Decompress -> (S||M): ", b64(signed_plain_recv))

sign_len = int.from_bytes(signed_plain_recv[:2], "big")
S_recv = signed_plain_recv[2:2+sign_len]
M_recv = signed_plain_recv[2+sign_len:]
print(f"\n\n\tExtracted Plain text M: ", M_recv.decode())

h2 = SHA1.new(M_recv)
print("\n\t[DP] Verify signature S with PU_a: ", b64(h2.digest()))

try:
    pkcs1_15.new(A_public).verify(h2, S_recv)
    verifid = True
except:
    verifid = False 
    raise ValueError("Error verifying!")

print(f"\n\n\t{"Valid" if verifid else "Invalid"}")


# from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# import os, base64

# def b64(data, maxlen=50):
#     s = base64.b64encode(data).decode()
#     return s if len(s) <= maxlen else s[:maxlen] + "..."

# # Key generation
# def generate_rsa_keys():
#     private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#     return private_key, private_key.public_key()

# # Signing 
# def sign(message_bytes, priv):
#     return priv.sign(message_bytes, asym_padding.PSS(
#         mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH
#     ), hashes.SHA256())

# def verify(message_bytes, signature, pub):
#     try:
#         pub.verify(signature, message_bytes, asym_padding.PSS(
#             mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH
#         ), hashes.SHA256())
#         return True
#     except:
#         return False

# # Hybrid encryption
# def encrypt(message_bytes, recipient_pub):
#     aes_key = AESGCM.generate_key(bit_length=256)
#     aesgcm = AESGCM(aes_key)
#     nonce = os.urandom(12)
#     ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
#     enc_key = recipient_pub.encrypt(aes_key, asym_padding.OAEP(
#         mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
#     ))
#     return {"enc_key": enc_key, "nonce": nonce, "ciphertext": ciphertext}

# def decrypt(enc_package, recipient_priv):
#     aes_key = recipient_priv.decrypt(enc_package["enc_key"], asym_padding.OAEP(
#         mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
#     ))
#     aesgcm = AESGCM(aes_key)
#     return aesgcm.decrypt(enc_package["nonce"], enc_package["ciphertext"], None)


# if __name__ == "__main__":
#     print("HYBRID CRYPTOGRAPHY SYSTEM (First Code Enhanced)\n")
    
#     # Generate sender (Alice) and recipient (Bob) keys
#     print("[KEY GEN] Generating RSA keys for Alice and Bob...")
#     alice_priv, alice_pub = generate_rsa_keys()
#     bob_priv, bob_pub = generate_rsa_keys()
#     print(f"[KEY] Alice's public key generated: 2048-bit RSA")
#     print(f"[KEY] Bob's public key generated: 2048-bit RSA\n")

#     message = b"UNIVERSITY OF RAJSHAHI"
#     print(f"[M]    Plaintext message: {message.decode()}")

#     # Sign message
#     print(f"\nSIGNING PROCESS (Alice)")
#     signature = sign(message, alice_priv)
#     print(f"[SIG]  Signature computed with Alice's private key: {b64(signature)}")
    
#     signed_message = signature + message  # simple concatenation
#     print(f"[||]   Concatenate signature and message (S || M): {b64(signed_message)}")

#     # Encrypt signed message
#     print(f"\nENCRYPTION PROCESS (Alice)")
#     print("[ENC]  Generating random AES-256 key for symmetric encryption...")
#     encrypted_package = encrypt(signed_message, bob_pub)
#     print(f"[ENC]  AES key encrypted with Bob's public key (RSA-OAEP): {b64(encrypted_package['enc_key'])}")
#     print(f"[ENC]  Generated nonce for AES-GCM: {b64(encrypted_package['nonce'])}")
#     print(f"[ENC]  AES-GCM ciphertext: {b64(encrypted_package['ciphertext'])}")
#     print(f"[PKG]  Complete encrypted package ready for transmission\n")

#     # Bob decrypts
#     print(f"\nDECRYPTION PROCESS (Bob)")
#     print("[DEC]  Decrypting AES key with Bob's private key...")
#     decrypted = decrypt(encrypted_package, bob_priv)
#     print(f"[DEC]  Successfully decrypted data: {b64(decrypted)}")

#     # Extract signature and message
#     sig_len = 256  # RSA-2048 signature size in bytes
#     received_sig = decrypted[:sig_len]
#     received_msg = decrypted[sig_len:]
    
#     print(f"\nSIGNATURE VERIFICATION (Bob)")
#     print(f"[SIG]  Extracted signature: {b64(received_sig)}")
#     print(f"[M]    Extracted message: {received_msg.decode()}")

#     # Verify signature
#     print(f"\n[VERIFY] Verifying signature with Alice's public key...")
#     valid = verify(received_msg, received_sig, alice_pub)

#     print(f"\nFINAL RESULTS")
#     print("Decrypted message:", received_msg.decode())
#     print("Signature valid?", valid)
#     print(f"Integrity check: {'PASS' if valid else 'FAIL'}")
#     print(f"Authentication: {'Alice confirmed as sender' if valid else 'Sender NOT authenticated'}")



# import os
# import base64
# import hashlib
# import hmac

# # -------------------- RSA-LIKE DEMO --------------------
# def generate_rsa_keypair():
#     # small fixed primes (demo only)
#     p, q = 3557, 2579
#     n = p * q
#     phi = (p - 1) * (q - 1)
#     e = 65537
#     d = pow(e, -1, phi)
#     return (d, n), (e, n)  # (private, public)

# def rsa_encrypt(data: bytes, pubkey):
#     e, n = pubkey
#     m = int.from_bytes(data, 'big')
#     c = pow(m, e, n)
#     return c.to_bytes((n.bit_length() + 7) // 8, 'big')

# def rsa_decrypt(data: bytes, privkey):
#     d, n = privkey
#     c = int.from_bytes(data, 'big')
#     m = pow(c, d, n)
#     return m.to_bytes((n.bit_length() + 7) // 8, 'big')

# # -------------------- Symmetric (PBKDF2 + XOR + HMAC) --------------------
# def derive_key(password: bytes, salt: bytes, length=32):
#     return hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=length)

# def encrypt_symmetric(plaintext: bytes, password: bytes):
#     salt = os.urandom(16)
#     key = derive_key(password, salt)
#     ciphertext = bytes([p ^ k for p, k in zip(plaintext, key * (len(plaintext)//len(key) + 1))])
#     mac = hmac.new(key, ciphertext, hashlib.sha256).digest()
#     return salt + mac + ciphertext

# def decrypt_symmetric(package: bytes, password: bytes):
#     salt = package[:16]
#     mac = package[16:48]
#     ciphertext = package[48:]
#     key = derive_key(password, salt)
#     calc_mac = hmac.new(key, ciphertext, hashlib.sha256).digest()
#     if not hmac.compare_digest(mac, calc_mac):
#         raise ValueError("Integrity check failed (HMAC mismatch)")
#     plaintext = bytes([p ^ k for p, k in zip(ciphertext, key * (len(ciphertext)//len(key) + 1))])
#     return plaintext

# # -------------------- SIGN / VERIFY (RSA + SHA256) --------------------
# def sign(message: bytes, privkey):
#     """Sign: hash the message, reduce mod n implicitly by pow(..., d, n)."""
#     hashed_int = int.from_bytes(hashlib.sha256(message).digest(), 'big')
#     d, n = privkey
#     sig_int = pow(hashed_int, d, n)  # computed modulo n
#     return sig_int.to_bytes((n.bit_length() + 7) // 8, 'big')

# def verify(message: bytes, signature: bytes, pubkey):
#     """Verify: decrypt signature and compare to (hash mod n)."""
#     e, n = pubkey
#     sig_int = int.from_bytes(signature, 'big')
#     check_int = pow(sig_int, e, n)  # this is in range [0,n-1]
#     hashed_int = int.from_bytes(hashlib.sha256(message).digest(), 'big')
#     # IMPORTANT: reduce hashed_int modulo n before comparing
#     return check_int == (hashed_int % n)

# # -------------------- HYBRID ENCRYPTION: RSA-seed + symmetric --------------------
# def hybrid_encrypt(message: bytes, recipient_pub):
#     # small session seed fits small RSA modulus
#     session_seed = os.urandom(2)                 # 2 bytes -> small value
#     encrypted_seed = rsa_encrypt(session_seed, recipient_pub)
#     sym_key = hashlib.sha256(session_seed).digest()  # derive full key deterministically
#     encrypted_message = encrypt_symmetric(message, sym_key)
#     return encrypted_seed + encrypted_message

# def hybrid_decrypt(package: bytes, recipient_priv):
#     key_len = (recipient_priv[1].bit_length() + 7) // 8
#     enc_seed = package[:key_len]
#     enc_message = package[key_len:]
#     session_seed_padded = rsa_decrypt(enc_seed, recipient_priv)
#     # rsa_decrypt returns full-length bytes (with leading zeros). Remove leading zeros:
#     session_seed = session_seed_padded.lstrip(b'\x00')
#     sym_key = hashlib.sha256(session_seed).digest()
#     return decrypt_symmetric(enc_message, sym_key)

# # -------------------- PGP-LIKE WORKFLOW --------------------
# def create_pgp_message(message, sender_priv, recipient_pub):
#     signature = sign(message, sender_priv)
#     signed_message = signature + message
#     encrypted_package = hybrid_encrypt(signed_message, recipient_pub)
#     return base64.b64encode(encrypted_package).decode('utf-8')

# def read_pgp_message(encoded_message, recipient_priv, sender_pub):
#     encrypted_package = base64.b64decode(encoded_message)
#     signed_message = hybrid_decrypt(encrypted_package, recipient_priv)
#     sig_len = (sender_pub[1].bit_length() + 7) // 8
#     signature = signed_message[:sig_len]
#     message = signed_message[sig_len:]
#     valid = verify(message, signature, sender_pub)
#     return message, valid

# # -------------------- DEMO --------------------
# if __name__ == "__main__":
#     print("Generating RSA-like keys...")
#     alice_priv, alice_pub = generate_rsa_keypair()
#     bob_priv, bob_pub = generate_rsa_keypair()

#     message = b"UNIVERSITY OF RAJSHAHI"
#     print("\nOriginal Message:", message.decode())

#     pgp_message = create_pgp_message(message, alice_priv, bob_pub)
#     print("\nPGP Message (base64):", pgp_message[:80] + "...")

#     decrypted, valid = read_pgp_message(pgp_message, bob_priv, alice_pub)
#     print("\nDecrypted Message:", decrypted.decode())
#     print("Signature Valid:", valid)
