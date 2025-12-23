const ECDH_ALGO = { name: "ECDH", namedCurve: "P-256" };
const AES_ALGO = { name: "AES-GCM", length: 256 };

// 1. Generate Keys (Extractable = true allows us to show the private key)
async function generateIdentityKeyPair() {
    return await window.crypto.subtle.generateKey(
        ECDH_ALGO,
        true, 
        ["deriveBits"]
    );
}

// 2. Export Public Key (spki)
async function exportKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

// 3. NEW: Export Private Key (pkcs8)
async function exportPrivateKey(key) {
    const exported = await window.crypto.subtle.exportKey("pkcs8", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

// 4. Import Public Key
async function importKey(pemData) {
    const binary = atob(pemData);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
    return await window.crypto.subtle.importKey("spki", buffer, ECDH_ALGO, true, []);
}

// 5. Compute Secret
async function computeSharedSecret(privateKey, publicKey) {
    return await window.crypto.subtle.deriveBits(
        { name: "ECDH", public: publicKey },
        privateKey,
        256
    );
}

// 6. Encrypt (Strict AES-GCM)
async function encryptWithSessionKey(sessionKey, text) {
    const encoded = new TextEncoder().encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, 
        sessionKey,
        encoded
    );
    return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
    };
}

// 7. Decrypt
async function decryptWithSessionKey(sessionKey, cipherBase64, ivBase64) {
    const cipherBuffer = Uint8Array.from(atob(cipherBase64), c => c.charCodeAt(0));
    const ivBuffer = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBuffer },
            sessionKey,
            cipherBuffer
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Decryption Failed:", e);
        throw new Error("Decryption Failed");
    }
}