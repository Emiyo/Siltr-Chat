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

            // Convert to base64 safely
            return btoa(String.fromCharCode.apply(null, combined));
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw new Error('Failed to encrypt message: ' + error.message);
        }
    }

    static async decryptMessage(encryptedMessage, symmetricKey) {
        try {
            if (!encryptedMessage || !symmetricKey) {
                throw new Error('Missing encrypted message or decryption key');
            }

            // Safely decode base64 with proper error handling
            let decodedData;
            try {
                // Remove any whitespace and validate base64 string
                const cleanBase64 = encryptedMessage.replace(/\s/g, '');
                if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
                    throw new Error('Invalid base64 format');
                }
                decodedData = atob(cleanBase64);
            } catch (base64Error) {
                throw new Error('Invalid base64 encoding: ' + base64Error.message);
            }

            // Convert decoded string to Uint8Array
            const combined = new Uint8Array(decodedData.split('').map(c => c.charCodeAt(0)));
            
            if (combined.length <= 12) {
                throw new Error('Encrypted data too short');
            }

            // Extract IV and encrypted data
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

    static async encryptFile(file, symmetricKey) {
        try {
            console.log('Starting file encryption process');
            console.log('File details:', {
                name: file.name,
                type: file.type,
                size: file.size
            });

            if (!file || !symmetricKey) {
                throw new Error('Missing file or encryption key');
            }

            if (file.size === 0) {
                throw new Error('Cannot encrypt empty file');
            }

            const buffer = await file.arrayBuffer();
            console.log('File loaded into buffer successfully, size:', buffer.byteLength);

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            console.log('Generated IV for encryption');

            console.log('Starting encryption...');
            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                symmetricKey,
                buffer
            );
            console.log('File encrypted successfully, size:', encryptedData.byteLength);

            const encryptedArray = new Uint8Array(encryptedData);
            const combined = new Uint8Array(iv.length + encryptedArray.length);
            combined.set(iv);
            combined.set(encryptedArray, iv.length);
            console.log('Combined IV and encrypted data, total size:', combined.length);

            // Create a new Blob with the encrypted data and preserve the original type
            const encryptedBlob = new Blob([combined], { type: file.type });
            console.log('Created encrypted blob:', {
                size: encryptedBlob.size,
                type: encryptedBlob.type,
                originalName: file.name,
                originalType: file.type
            });

            return {
                blob: encryptedBlob,
                key: symmetricKey,
                originalType: file.type,
                originalName: file.name
            };
        } catch (error) {
            console.error('Detailed encryption error:', error);
            console.error('Error stack:', error.stack);
            throw new Error(`Failed to encrypt file: ${error.message}`);
        }
    }

    static async decryptFile(encryptedBlob, symmetricKey, originalType) {
        try {
            console.log('Starting file decryption');
            console.log('Input blob:', {
                size: encryptedBlob.size,
                type: encryptedBlob.type,
                targetType: originalType
            });

            const arrayBuffer = await encryptedBlob.arrayBuffer();
            console.log('Blob loaded into buffer, size:', arrayBuffer.byteLength);

            const combined = new Uint8Array(arrayBuffer);
            console.log('Combined data size:', combined.length);
            
            if (combined.length <= 12) {
                throw new Error('Invalid encrypted data: too short');
            }

            // Extract IV and encrypted data
            const iv = combined.slice(0, 12);
            const encryptedData = combined.slice(12);
            console.log('Extracted IV and encrypted data:', {
                ivSize: iv.length,
                encryptedSize: encryptedData.length
            });

            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                symmetricKey,
                encryptedData
            );
            console.log('Data decrypted successfully, size:', decryptedData.byteLength);

            // Create a new Blob with the decrypted data and original type
            console.log('Creating decrypted blob with type:', originalType);
            const decryptedBlob = new Blob([decryptedData], { type: originalType });
            console.log('Decrypted blob created:', {
                size: decryptedBlob.size,
                type: decryptedBlob.type,
                expectedType: originalType
            });
            return decryptedBlob;
        } catch (error) {
            console.error('Detailed decryption error:', error);
            console.error('Error stack:', error.stack);
            throw new Error('Failed to decrypt file: ' + error.message);
        }
    }
}
