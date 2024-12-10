// Perfect Forward Secrecy Implementation
class PFSManager {
    constructor() {
        this.currentKeyPair = null;
        this.keyRotationInterval = 5 * 60 * 1000; // 5 minutes
        this.init();
    }

    async init() {
        await this.rotateKeys();
        // Set up periodic key rotation
        setInterval(() => this.rotateKeys(), this.keyRotationInterval);
    }

    async rotateKeys() {
        try {
            // Generate new key pair
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true, // extractable
                ["deriveKey", "deriveBits"]
            );
            
            this.currentKeyPair = keyPair;
            
            // Export public key for sharing
            const publicKeyBuffer = await window.crypto.subtle.exportKey(
                "spki",
                keyPair.publicKey
            );
            
            // Broadcast new public key to other participants
            if (window.socket) {
                window.socket.emit('new_public_key', {
                    publicKey: arrayBufferToBase64(publicKeyBuffer)
                });
            }
            
            console.log('Generated new key pair for PFS');
        } catch (error) {
            console.error('Error rotating keys:', error);
        }
    }

    async getSharedSecret(peerPublicKeyB64) {
        try {
            // Import peer's public key
            const peerPublicKeyBuffer = base64ToArrayBuffer(peerPublicKeyB64);
            const peerPublicKey = await window.crypto.subtle.importKey(
                "spki",
                peerPublicKeyBuffer,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                []
            );

            // Derive shared secret
            const sharedSecret = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: peerPublicKey
                },
                this.currentKeyPair.privateKey,
                256
            );

            return sharedSecret;
        } catch (error) {
            console.error('Error generating shared secret:', error);
            throw error;
        }
    }

    getCurrentPublicKey() {
        return this.currentKeyPair?.publicKey;
    }
}

// Utility functions
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Initialize PFS manager
const pfsManager = new PFSManager();
