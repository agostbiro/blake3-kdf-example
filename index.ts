// TODO: From the official Rust implementation, we'd use the `blake3::derive_key` function. Verify that the usage in this file is equivalent.
import { blake3 } from '@noble/hashes/blake3';
import { scrypt } from '@noble/hashes/scrypt';

// Derive master key from user password using scrypt to enrich the effective entropy of the presumably weak user password.
// This is an expensive operation.
const masterKey = scrypt('user-password', 'unique-salt-for-user', { N: 2 ** 17, r: 8, p: 1, dkLen: 32 });

// Our application needs keys for different purposes: encryption and message authentication.
// It's bad practice to use the same key for different purposes, so we need to derive further keys from our master key.
// Since the master key was derived with a strong password-based key derivation function, we can use a cheap to compute key derivation function (KDF) to derive additional keys.
// We choose BLAKE3 KDF for this purpose as it's a state-of-the-art KDF.
// As an alternative we could use the HMAC-based HKDF construction, but this has two drawbacks:
// - It has an awkward interface for applications that already have a cryptographically secure pseudorandom key (and thus don't need its extract phase).
// - It can cause subtle problems in applications that use standalone HMAC for other purposes (which we do).

// Using the context format recommended by the BLAKE3 docs: "[application] [commit timestamp] [purpose]"
const dataEncryptionKey = blake3('My Application 2025-02-03 11:30:00 Data Encryption Key', {key: masterKey});
const hmacKey = blake3('My Application 2025-02-03 11:30:00 HMAC Key', {key: masterKey});

console.log("master key:", Buffer.from(masterKey).toString("hex"));
console.log("data encryption key:", Buffer.from(dataEncryptionKey).toString("hex"));
console.log("hmac key:", Buffer.from(hmacKey).toString("hex"));
