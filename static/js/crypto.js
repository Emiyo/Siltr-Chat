// Crypto utilities for E2E encryption with Perfect Forward Secrecy
class CryptoManager {
    // Generate ECDH key pair for Perfect Forward Secrecy
    static async generateDHKeyPair() {
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256" // Using NIST P-256 curve
                },
                true, // extractable
                ["deriveKey", "deriveBits"] // Key usage
            );
            console.log('Generated new DH key pair');
            return keyPair;
        } catch (error) {
            console.error('Error generating DH key pair:', error);
            throw new Error('Failed to generate DH key pair');
        }
    }

    // Export public DH key for sharing
    static async exportPublicKey(publicKey) {
        try {
            const exported = await window.crypto.subtle.exportKey(
                "spki",
                publicKey
            );
            const base64Key = btoa(String.fromCharCode(...new Uint8Array(exported)));
            console.log('Exported public key successfully');
            return base64Key;
        } catch (error) {
            console.error('Error exporting public key:', error);
            throw new Error('Failed to export public key');
        }
    }

    // Import peer's public DH key
    static async importPublicKey(base64Key) {
        try {
            const binaryKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
            const importedKey = await window.crypto.subtle.importKey(
                "spki",
                binaryKey,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                [] // No key usage needed for public key
            );
            console.log('Imported peer public key successfully');
            return importedKey;
        } catch (error) {
            console.error('Error importing public key:', error);
            throw new Error('Failed to import public key');
        }
    }

    // Derive shared secret using private key and peer's public key
    static async deriveSharedSecret(privateKey, peerPublicKey) {
        try {
            // Generate shared bits
            const sharedBits = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: peerPublicKey
                },
                privateKey,
                256 // Generate 256 bits
            );

            // Convert to AES key
            const sharedKey = await window.crypto.subtle.importKey(
                "raw",
                sharedBits,
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );
            console.log('Derived shared secret successfully');
            return sharedKey;
        } catch (error) {
            console.error('Error deriving shared secret:', error);
            throw new Error('Failed to derive shared secret');
        }
    }

    // Encrypt message using shared key
    static async encryptMessage(message, sharedKey) {
        try {
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encodedMessage = new TextEncoder().encode(message);

            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                sharedKey,
                encodedMessage
            );

            // Combine IV and encrypted data
            const combined = new Uint8Array(iv.length + encryptedData.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encryptedData), iv.length);

            return btoa(String.fromCharCode(...combined));
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw new Error('Failed to encrypt message');
        }
    }

    // Decrypt message using shared key
    static async decryptMessage(encryptedMessage, sharedKey) {
        try {
            const combined = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
            
            // Extract IV and encrypted data
            const iv = combined.slice(0, 12);
            const encryptedData = combined.slice(12);

            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                sharedKey,
                encryptedData
            );

            return new TextDecoder().decode(decryptedData);
        } catch (error) {
            console.error('Error decrypting message:', error);
            throw new Error('Failed to decrypt message');
        }
    }

    // Legacy RSA key pair generation (kept for compatibility)
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

            // Convert to base64 safely using URL-safe format
            const base64Data = btoa(String.fromCharCode.apply(null, combined))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');
            
            console.log('Encrypted message length:', base64Data.length);
            return base64Data;
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

            console.log('Attempting to decrypt message of length:', encryptedMessage.length);
            
            // Restore base64 standard characters
            let standardBase64 = encryptedMessage
                .replace(/-/g, '+')
                .replace(/_/g, '/');

            // Add back padding if needed
            while (standardBase64.length % 4) {
                standardBase64 += '=';
            }

            // Remove any remaining whitespace
            standardBase64 = standardBase64.replace(/\s/g, '');

            // Validate base64 format
            if (!/^[A-Za-z0-9+/]*={0,3}$/.test(standardBase64)) {
                console.error('Invalid base64 string:', standardBase64);
                throw new Error('Invalid base64 format');
            }

            let decodedData;
            try {
                decodedData = atob(standardBase64);
                console.log('Base64 decoded successfully, length:', decodedData.length);
            } catch (base64Error) {
                console.error('Base64 decoding error:', base64Error);
                throw new Error('Base64 decoding failed: ' + base64Error.message);
            }

            // Convert decoded string to Uint8Array
            const combined = new Uint8Array(decodedData.split('').map(c => c.charCodeAt(0)));
            console.log('Decoded data length:', combined.length);
            
            if (combined.length <= 12) {
                throw new Error('Decoded data too short (minimum 12 bytes for IV)');
            }

            // Extract IV and encrypted data
            const iv = combined.slice(0, 12);
            const encryptedData = combined.slice(12);
            console.log('IV length:', iv.length, 'Encrypted data length:', encryptedData.length);

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

            console.log('Message decrypted successfully');
            return decryptedText;
        } catch (error) {
            console.error('Decryption error details:', error);
            console.error('Error stack:', error.stack);
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

    static async encryptFile(file, symmetricKey, onProgress = null) {
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

            // Validate file size (50MB limit)
            const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB in bytes
            if (file.size > MAX_FILE_SIZE) {
                throw new Error('File size exceeds the maximum limit of 50MB');
            }

            // Report initial progress
            if (onProgress) {
                onProgress({
                    phase: 'loading',
                    progress: 0,
                    message: 'Loading file...'
                });
            }

            const buffer = await file.arrayBuffer();
            console.log('File loaded into buffer successfully, size:', buffer.byteLength);

            // Report loading complete
            if (onProgress) {
                onProgress({
                    phase: 'encrypting',
                    progress: 0,
                    message: 'Starting encryption...'
                });
            }

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

            // Report completion
            if (onProgress) {
                onProgress({
                    phase: 'complete',
                    progress: 100,
                    message: 'Encryption complete'
                });
            }

            return {
                blob: encryptedBlob,
                key: symmetricKey,
                originalType: file.type,
                originalName: file.name
            };
        } catch (error) {
            console.error('Detailed encryption error:', error);
            console.error('Error stack:', error.stack);
            
            // Report error through progress callback
            if (onProgress) {
                onProgress({
                    phase: 'error',
                    progress: 0,
                    message: `Encryption failed: ${error.message}`
                });
            }
            
            // Provide more user-friendly error messages
            let errorMessage = 'Failed to encrypt file';
            if (error.message.includes('maximum limit')) {
                errorMessage = 'File is too large. Maximum size is 50MB.';
            } else if (error.message.includes('key')) {
                errorMessage = 'Encryption key error. Please try again.';
            } else if (error.name === 'QuotaExceededError') {
                errorMessage = 'Not enough storage space available.';
            }
            
            throw new Error(errorMessage);
        }
    }

    static async decryptFile(encryptedBlob, symmetricKey, originalType, onProgress = null) {
        try {
            console.log('Starting file decryption');
            console.log('Input blob:', {
                size: encryptedBlob.size,
                type: encryptedBlob.type,
                targetType: originalType
            });

            // Report initial progress
            if (onProgress) {
                onProgress({
                    phase: 'loading',
                    progress: 0,
                    message: 'Loading encrypted file...'
                });
            }

            const arrayBuffer = await encryptedBlob.arrayBuffer();
            console.log('Blob loaded into buffer, size:', arrayBuffer.byteLength);

            // Report decryption start
            if (onProgress) {
                onProgress({
                    phase: 'decrypting',
                    progress: 25,
                    message: 'Decrypting file...'
                });
            }

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

            // Report completion
            if (onProgress) {
                onProgress({
                    phase: 'complete',
                    progress: 100,
                    message: 'Decryption complete'
                });
            }

            return decryptedBlob;
        } catch (error) {
            console.error('Detailed decryption error:', error);
            console.error('Error stack:', error.stack);

            // Report error through progress callback
            if (onProgress) {
                onProgress({
                    phase: 'error',
                    progress: 0,
                    message: `Decryption failed: ${error.message}`
                });
            }

            // Provide user-friendly error messages
            let errorMessage = 'Failed to decrypt file';
            if (error.name === 'OperationError') {
                errorMessage = 'Invalid encryption key or corrupted file.';
            } else if (error.message.includes('IV')) {
                errorMessage = 'File appears to be corrupted or not properly encrypted.';
            }

            throw new Error(errorMessage);
        }
    }
}