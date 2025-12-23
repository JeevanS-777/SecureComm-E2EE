class RatchetSession {
    constructor() {
        this.rootKey = null;      // CryptoKey (HKDF)
        this.chainKeyBits = null; // ArrayBuffer (Raw Bytes)
        this.sessionKey = null;   // CryptoKey (AES-GCM)
    }

    // 1. Initialize with Shared Secret (from ECDH)
    async init(sharedSecretBuffer) {
        // Import Shared Secret as an HKDF Master Key
        this.rootKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecretBuffer,
            { name: "HKDF" }, 
            false,
            ["deriveBits"]
        );

        // Derive the Initial Chain Key (32 bytes) from Root Key
        this.chainKeyBits = await window.crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array(32), // Empty salt for init
                info: new TextEncoder().encode("init-chain")
            },
            this.rootKey,
            256 // 256 bits (32 bytes)
        );
    }

    // 2. RATCHET FORWARD (The "Double Ratchet" Core)
    async ratchetForward() {
        if (!this.chainKeyBits) throw new Error("Ratchet not initialized");

        // A. Import the current Chain Key as an HKDF Key
        const currentChainKeyObj = await window.crypto.subtle.importKey(
            "raw",
            this.chainKeyBits,
            { name: "HKDF" },
            false,
            ["deriveBits"]
        );

        // B. KDF Step: Generate 64 bytes of output
        //    - First 32 bytes = NEW Chain Key
        //    - Next 32 bytes = SESSION Key (for AES)
        const outputMaterial = await window.crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array(32),
                info: new TextEncoder().encode("ratchet-step")
            },
            currentChainKeyObj,
            512 // Request 512 bits (64 bytes)
        );

        // C. Split the 64 bytes into two 32-byte chunks
        const outputArray = new Uint8Array(outputMaterial);
        const newChainBits = outputArray.slice(0, 32);
        const sessionKeyBits = outputArray.slice(32, 64);

        // D. Update State
        this.chainKeyBits = newChainBits.buffer; // Rotate the Chain Key

        // E. Import the Session Key part as strict AES-GCM
        this.sessionKey = await window.crypto.subtle.importKey(
            "raw",
            sessionKeyBits,
            { name: "AES-GCM", length: 256 }, 
            true,
            ["encrypt", "decrypt"]
        );

        return this.sessionKey;
    }

    async getFingerprint() {
        if(!this.sessionKey) return "Waiting for Handshake...";
        
        // Export the FULL Session Key (AES-256)
        const raw = await window.crypto.subtle.exportKey("raw", this.sessionKey);
        
        // Convert to Full Hex String for Verification
        return Array.from(new Uint8Array(raw))
            .map(b => b.toString(16).padStart(2,'0'))
            .join('');
    }
}