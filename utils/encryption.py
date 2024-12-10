import os
import base64
import json
import logging
from typing import Dict, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

class EncryptionWrapper:
    """Simplified wrapper class for handling E2E encryption operations using Fernet"""
    
    def __init__(self):
        self.channel_keys: Dict[str, Dict[str, str]] = {}  # channelId -> {userId: encryptedKey}
    
    def generate_key(self) -> str:
        """Generate a new Fernet key"""
        try:
            key = Fernet.generate_key()
            return base64.b64encode(key).decode('utf-8')
        except Exception as e:
            logger.error(f"Error generating encryption key: {str(e)}")
            raise

    def store_key(self, channel_id: str, user_id: str, encrypted_key: str) -> None:
        """Store an encrypted channel key for a user"""
        try:
            if channel_id not in self.channel_keys:
                self.channel_keys[channel_id] = {}
            self.channel_keys[channel_id][user_id] = encrypted_key
            logger.info(f"Stored key for channel {channel_id} and user {user_id}")
        except Exception as e:
            logger.error(f"Error storing encryption key: {str(e)}")
            raise

    def get_key(self, channel_id: str, user_id: str) -> Optional[str]:
        """Get an encrypted channel key for a user"""
        try:
            return self.channel_keys.get(channel_id, {}).get(user_id)
        except Exception as e:
            logger.error(f"Error retrieving encryption key: {str(e)}")
            return None

    def encrypt_message(self, message: str, key: str) -> Dict[str, str]:
        """Encrypt a message using Fernet"""
        try:
            # Decode the base64 key
            key_bytes = base64.b64decode(key.encode())
            f = Fernet(key_bytes)
            
            # Encrypt the message
            encrypted_data = f.encrypt(message.encode())
            
            return {
                'encrypted': base64.b64encode(encrypted_data).decode('utf-8'),
                'key_id': key[:8]  # Store first 8 chars of key for identification
            }
        except Exception as e:
            logger.error(f"Error encrypting message: {str(e)}")
            raise

    def decrypt_message(self, encrypted_data: Dict[str, str], key: str) -> Optional[str]:
        """Decrypt a message using Fernet"""
        try:
            if not isinstance(encrypted_data, dict) or 'encrypted' not in encrypted_data:
                raise ValueError("Invalid encrypted message format")

            # Verify key matches
            if encrypted_data.get('key_id') != key[:8]:
                raise ValueError("Key mismatch")

            # Decode the key and create Fernet instance
            key_bytes = base64.b64decode(key.encode())
            f = Fernet(key_bytes)
            
            # Decrypt the message
            encrypted = base64.b64decode(encrypted_data['encrypted'].encode())
            decrypted_bytes = f.decrypt(encrypted)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting message: {str(e)}")
            return None

    def rotate_key(self, channel_id: str) -> Optional[str]:
        """Generate a new key for a channel and return it"""
        try:
            new_key = self.generate_key()
            # Clear old keys for this channel
            self.channel_keys[channel_id] = {}
            return new_key
        except Exception as e:
            logger.error(f"Error rotating channel key: {str(e)}")
            return None
