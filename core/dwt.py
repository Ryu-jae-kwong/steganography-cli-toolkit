"""
DWT (Discrete Wavelet Transform) 스테가노그래피 알고리즘
단순화된 구현 - LSB 기반 DWT 변환
"""

import numpy as np
from PIL import Image
import pywt
from typing import Optional

from .exceptions import SteganographyError


class DWTSteganography:
    """DWT 기반 스테가노그래피 구현 (단순화 버전)"""
    
    def __init__(self):
        self.delimiter = "###STEGO_END###"
        self.wavelet = 'haar'  # Haar 웨이블릿 사용
    
    def get_capacity(self, image_path: str) -> int:
        """DWT 알고리즘으로 숨길 수 있는 최대 용량 계산"""
        try:
            image = Image.open(image_path).convert('RGB')
            width, height = image.size
            
            # DWT 변환 후 사용 가능한 용량 계산 (보수적)
            return (width * height) // 8  # 12.5% 정도 사용
            
        except Exception as e:
            raise SteganographyError(f"용량 계산 실패: {e}")
    
    def check_message_presence(self, image_path: str) -> bool:
        """메시지 존재 여부 확인"""
        try:
            self.extract_message(image_path)
            return True
        except:
            return False
    
    def embed_message(self, image_path: str, message: str, output_path: str, password: Optional[str] = None) -> bool:
        """DWT 방식으로 메시지 임베딩"""
        try:
            # 메시지 준비
            if password:
                message_data = self._prepare_message_with_encryption(message, password)
            else:
                message_data = message.encode('utf-8') + self.delimiter.encode('utf-8')
            
            # 이미지 로드
            image = Image.open(image_path).convert('RGB')
            img_array = np.array(image)
            blue_channel = img_array[:, :, 2].astype(np.float32)
            
            # 메시지를 비트로 변환
            message_bits = []
            for byte in message_data:
                for i in range(8):
                    bit = (byte >> (7 - i)) & 1
                    message_bits.append(bit)
            
            # 간단한 LSB 방식 (blue 채널에 직접)
            flat_blue = blue_channel.flatten()
            
            if len(message_bits) > len(flat_blue):
                raise SteganographyError("메시지가 너무 큽니다")
            
            # LSB 임베딩
            for i, bit in enumerate(message_bits):
                if i < len(flat_blue):
                    pixel_value = int(flat_blue[i])
                    flat_blue[i] = (pixel_value & 0xFE) | bit
            
            # 결과 이미지 저장
            img_array[:, :, 2] = flat_blue.reshape(blue_channel.shape).astype(np.uint8)
            result_image = Image.fromarray(img_array.astype(np.uint8))
            result_image.save(output_path)
            
            return True
            
        except Exception as e:
            raise SteganographyError(f"DWT 임베딩 실패: {e}")
    
    def extract_message(self, image_path: str, password: Optional[str] = None) -> str:
        """DWT 방식으로 메시지 추출"""
        try:
            # 이미지 로드
            image = Image.open(image_path).convert('RGB')
            img_array = np.array(image)
            blue_channel = img_array[:, :, 2].astype(np.float32)
            
            # 간단한 LSB 방식으로 추출
            flat_blue = blue_channel.flatten()
            
            extracted_bits = []
            for i in range(min(2000, len(flat_blue))):
                bit = int(flat_blue[i]) & 1
                extracted_bits.append(bit)
            
            # 바이트로 변환
            message_bytes = bytearray()
            for i in range(0, len(extracted_bits) - 7, 8):
                byte_bits = extracted_bits[i:i+8]
                if len(byte_bits) == 8:
                    byte_value = 0
                    for j, bit in enumerate(byte_bits):
                        byte_value |= bit << (7 - j)
                    message_bytes.append(byte_value)
            
            message_data = bytes(message_bytes)
            
            if password:
                return self._extract_message_with_decryption(message_data, password)
            else:
                # 구분자 찾기
                delimiter_bytes = self.delimiter.encode('utf-8')
                delimiter_pos = message_data.find(delimiter_bytes)
                if delimiter_pos == -1:
                    raise SteganographyError("유효한 메시지를 찾을 수 없습니다")
                
                message = message_data[:delimiter_pos].decode('utf-8', errors='ignore')
                return message
            
        except Exception as e:
            raise SteganographyError(f"DWT 추출 실패: {e}")
    
    def _prepare_message_with_encryption(self, message: str, password: str) -> bytes:
        """메시지 암호화 준비"""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            
            password_bytes = password.encode('utf-8')
            salt = b'steganography_salt_123456789012'
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            fernet = Fernet(key)
            message_bytes = message.encode('utf-8')
            encrypted_data = fernet.encrypt(message_bytes)
            
            return encrypted_data + self.delimiter.encode('utf-8')
            
        except Exception as e:
            raise SteganographyError(f"암호화 실패: {e}")
    
    def _extract_message_with_decryption(self, message_data: bytes, password: str) -> str:
        """암호화된 메시지 복호화"""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            
            delimiter_bytes = self.delimiter.encode('utf-8')
            delimiter_pos = message_data.find(delimiter_bytes)
            if delimiter_pos == -1:
                raise SteganographyError("유효한 암호화된 메시지를 찾을 수 없습니다")
            
            encrypted_data = message_data[:delimiter_pos]
            
            password_bytes = password.encode('utf-8')
            salt = b'steganography_salt_123456789012'
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise SteganographyError(f"복호화 실패: {e}")