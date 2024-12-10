// Crypto utilities for E2E encryption
class CryptoManager {
    static async generateKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );
        return keyPair;
    }

    static async exportPublicKey(publicKey) {
        const exported = await window.crypto.subtle.exportKey(
            "spki",
            publicKey
        );
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    static async generateSymmetricKey() {
        try {
            return await window.crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );
        } catch (error) {
            console.error('Error generating symmetric key:', error);
            throw new Error('Failed to generate encryption key');
        }
    }

    static async encryptMessage(message, symmetricKey) {
        try {
            if (!message || !symmetricKey) {
                throw new Error('Missing message or encryption key');
            }

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encodedMessage = new TextEncoder().encode(message);

            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                symmetricKey,
                encodedMessage
            );

            const encryptedArray = new Uint8Array(encryptedData);
            const combined = new Uint8Array(iv.length + encryptedArray.length);
            combined.set(iv);
            combined.set(encryptedArray, iv.length);

            return btoa(String.fromCharCode(...combined));
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw new Error('Failed to encrypt message');
        }
    }

    static async decryptMessage(encryptedMessage, symmetricKey) {
        try {
            if (!encryptedMessage || !symmetricKey) {
                throw new Error('Missing encrypted message or decryption key');
            }

            // Decode base64 to get the combined IV + encrypted data
            const combined = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
            
            // Extract IV (first 12 bytes) and encrypted data
            const iv = combined.slice(0, 12);
            const encryptedData = combined.slice(12);

            // Decrypt the data
            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                symmetricKey,
                encryptedData
            );

            // Convert decrypted array buffer to string
            const decryptedText = new TextDecoder().decode(decryptedData);
            if (!decryptedText) {
                throw new Error('Decrypted text is empty');
            }

            return decryptedText;
        } catch (error) {
            console.error('Decryption error details:', error);
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    static async exportSymmetricKey(symmetricKey) {
        const exported = await window.crypto.subtle.exportKey(
            "raw",
            symmetricKey
        );
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    static async importSymmetricKey(keyData) {
        const rawKey = new Uint8Array(
            atob(keyData).split('').map(char => char.charCodeAt(0))
        );
        return await window.crypto.subtle.importKey(
            "raw",
            rawKey,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    }
}
