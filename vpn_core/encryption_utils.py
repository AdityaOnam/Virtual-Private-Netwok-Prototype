"""
Encryption utilities for LeAmitVPN
Provides additional encryption layer on top of WireGuard
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional

from .logger import get_logger


class EncryptionManager:
    """Manages encryption operations for LeAmitVPN"""
    
    def __init__(self, password: Optional[str] = None):
        """
        Initialize encryption manager
        
        Args:
            password (str, optional): Password for key derivation
        """
        self.logger = get_logger(__name__)
        self.password = password
        self.key = None
        
        if password:
            self.key = self._derive_key(password)
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password (str): Password to derive key from
            salt (bytes, optional): Salt for key derivation
            
        Returns:
            bytes: Derived encryption key
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def generate_key(self) -> bytes:
        """Generate a random encryption key"""
        return Fernet.generate_key()
    
    def encrypt_data(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using Fernet encryption
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            Tuple[bytes, bytes]: (encrypted_data, salt)
        """
        if not self.key:
            raise ValueError("No encryption key available")
        
        try:
            f = Fernet(self.key)
            encrypted_data = f.encrypt(data)
            return encrypted_data, b''  # Fernet includes salt internally
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: bytes, salt: bytes = b'') -> bytes:
        """
        Decrypt data using Fernet encryption
        
        Args:
            encrypted_data (bytes): Encrypted data
            salt (bytes): Salt (not used with Fernet, kept for compatibility)
            
        Returns:
            bytes: Decrypted data
        """
        if not self.key:
            raise ValueError("No encryption key available")
        
        try:
            f = Fernet(self.key)
            decrypted_data = f.decrypt(encrypted_data)
            return decrypted_data
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_file(self, file_path: str, output_path: str) -> bool:
        """
        Encrypt a file
        
        Args:
            file_path (str): Path to file to encrypt
            output_path (str): Path for encrypted file
            
        Returns:
            bool: True if successful
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data, salt = self.encrypt_data(data)
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info(f"File encrypted: {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File encryption failed: {e}")
            return False
    
    def decrypt_file(self, file_path: str, output_path: str) -> bool:
        """
        Decrypt a file
        
        Args:
            file_path (str): Path to encrypted file
            output_path (str): Path for decrypted file
            
        Returns:
            bool: True if successful
        """
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"File decrypted: {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File decryption failed: {e}")
            return False


class HashUtils:
    """Utility functions for hashing"""
    
    @staticmethod
    def sha256_hash(data: bytes) -> str:
        """Calculate SHA256 hash of data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def md5_hash(data: bytes) -> str:
        """Calculate MD5 hash of data"""
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of a file
        
        Args:
            file_path (str): Path to file
            algorithm (str): Hash algorithm ('sha256' or 'md5')
            
        Returns:
            str: Hexadecimal hash of the file
        """
        hash_func = hashlib.sha256 if algorithm == 'sha256' else hashlib.md5
        
        with open(file_path, 'rb') as f:
            hash_obj = hash_func()
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()


class KeyGenerator:
    """Generate various types of keys for VPN"""
    
    @staticmethod
    def generate_wireguard_keys() -> Tuple[str, str]:
        """
        Generate WireGuard key pair
        
        Returns:
            Tuple[str, str]: (private_key, public_key)
        """
        import subprocess
        
        try:
            # Generate private key
            private_key_result = subprocess.run(
                ['wg', 'genkey'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if private_key_result.returncode != 0:
                raise Exception("Failed to generate private key")
            
            private_key = private_key_result.stdout.strip()
            
            # Generate public key
            public_key_result = subprocess.run(
                ['wg', 'pubkey'],
                input=private_key,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if public_key_result.returncode != 0:
                raise Exception("Failed to generate public key")
            
            public_key = public_key_result.stdout.strip()
            
            return private_key, public_key
            
        except Exception as e:
            raise Exception(f"Key generation failed: {e}")
    
    @staticmethod
    def generate_preshared_key() -> str:
        """
        Generate WireGuard preshared key
        
        Returns:
            str: Preshared key
        """
        import subprocess
        
        try:
            result = subprocess.run(
                ['wg', 'genkey'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise Exception("Failed to generate preshared key")
            
            return result.stdout.strip()
            
        except Exception as e:
            raise Exception(f"Preshared key generation failed: {e}")
    
    @staticmethod
    def generate_random_password(length: int = 32) -> str:
        """
        Generate a random password
        
        Args:
            length (int): Length of password
            
        Returns:
            str: Random password
        """
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        return password


class SecureConfig:
    """Secure configuration file handling"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        """
        Initialize secure config handler
        
        Args:
            encryption_manager (EncryptionManager): Encryption manager instance
        """
        self.encryption_manager = encryption_manager
        self.logger = get_logger(__name__)
    
    def save_secure_config(self, config_data: dict, file_path: str) -> bool:
        """
        Save configuration data encrypted
        
        Args:
            config_data (dict): Configuration data
            file_path (str): Path to save encrypted config
            
        Returns:
            bool: True if successful
        """
        try:
            import json
            
            # Convert to JSON
            json_data = json.dumps(config_data, indent=2)
            
            # Encrypt
            encrypted_data, salt = self.encryption_manager.encrypt_data(json_data.encode())
            
            # Save to file
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info(f"Secure config saved: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save secure config: {e}")
            return False
    
    def load_secure_config(self, file_path: str) -> Optional[dict]:
        """
        Load and decrypt configuration data
        
        Args:
            file_path (str): Path to encrypted config file
            
        Returns:
            dict: Decrypted configuration data or None if failed
        """
        try:
            import json
            
            # Read encrypted data
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            
            # Parse JSON
            config_data = json.loads(decrypted_data.decode())
            
            self.logger.info(f"Secure config loaded: {file_path}")
            return config_data
            
        except Exception as e:
            self.logger.error(f"Failed to load secure config: {e}")
            return None


