"""
DWT (Discrete Wavelet Transform) 스테가노그래피 알고리즘
웨이블릿 변환을 사용한 주파수 도메인 기법
"""

import numpy as np
from PIL import Image
import pywt
from typing import Optional

from .exceptions import SteganographyError


class DWTSteganography:
    """DWT 기반 스테가노그래피 구현"""
    
    def __init__(self):
        self.delimiter = "###STEGO_END###"  # DWT용 구분자
        self.wavelet = 'haar'  # Haar 웨이블릿 사용
    
    def get_capacity(self, image_path: str) -> int:
        """DWT 알고리즘으로 숨길 수 있는 최대 용량 계산"""
        try:
            image = Image.open(image_path).convert('RGB')
            width, height = image.size
            
            # Haar 웨이블릿 변환 후 HH 계수 개수
            # 일반적으로 원본 크기의 1/4
            hh_size = (width // 2) * (height // 2)
            
            # 각 HH 계수당 1비트 임베딩 가능
            capacity_bits = hh_size
            return capacity_bits // 8
            
        except Exception as e:
            raise SteganographyError(f"용량 계산 실패: {e}")
    
    def check_message_presence(self, image_path: str) -> bool:
        """메시지 존재 여부 확인"""
        try:
            image = Image.open(image_path).convert('RGB')
            blue_channel = np.array(image)[:, :, 2]
            
            # DWT 변환
            coeffs2 = pywt.dwt2(blue_channel, self.wavelet)
            LL, (LH, HL, HH) = coeffs2
            
            # HH 계수들에서 패턴 확인
            if HH.size > 0:
                # 첫 몇 계수의 LSB 확인
                hh_uint8 = HH.astype(np.uint8)
                first_bits = []
                for i in range(min(32, len(hh_uint8.flat))):
                    first_bits.append(hh_uint8.flat[i] & 1)
                
                # 패턴이 있는지 확인 (너무 균일하지 않아야 함)
                bit_sum = sum(first_bits)
                return 0.3 <= bit_sum / len(first_bits) <= 0.7
            
            return False
            
        except Exception:
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
            
            # Blue 채널 사용
            blue_channel = img_array[:, :, 2].astype(np.float32)
            
            # 메시지를 비트로 변환
            message_bits = []
            for byte in message_data:
                for bit in format(byte, '08b'):
                    message_bits.append(int(bit))
            
            # DWT 변환
            coeffs2 = pywt.dwt2(blue_channel, self.wavelet)
            LL, (LH, HL, HH) = coeffs2
            
            # 용량 체크
            if len(message_bits) > HH.size:
                raise SteganographyError("메시지가 너무 큽니다")
            
            # HH 계수를 정수형으로 변환
            HH_modified = HH.copy()
            
            # 메시지 비트를 HH 계수의 LSB에 임베딩
            flat_hh = HH_modified.flatten()
            for i, bit in enumerate(message_bits):
                if i < len(flat_hh):
                    # LSB 조작: (coeff & 0xFE) | bit
                    coeff_int = int(flat_hh[i])
                    flat_hh[i] = (coeff_int & 0xFE) | bit
            
            # 다시 원래 형태로 변환
            HH_modified = flat_hh.reshape(HH.shape)
            
            # 역 DWT 변환
            coeffs_modified = LL, (LH, HL, HH_modified)
            blue_restored = pywt.idwt2(coeffs_modified, self.wavelet)
            
            # 결과 이미지 생성
            img_array[:, :, 2] = np.clip(blue_restored, 0, 255).astype(np.uint8)
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
            
            # DWT 변환
            coeffs2 = pywt.dwt2(blue_channel, self.wavelet)
            LL, (LH, HL, HH) = coeffs2
            
            # HH 계수에서 LSB 추출
            flat_hh = HH.flatten()
            extracted_bits = []
            
            # 충분한 비트를 추출하기 위해 최대 추출량 증가
            max_bits_needed = 2000  # 더 많은 비트 추출
            
            for i, coeff in enumerate(flat_hh):
                if i >= max_bits_needed:
                    break
                bit = int(coeff) & 1
                extracted_bits.append(bit)
            
            # 비트를 바이트로 변환
            message_bytes = bytearray()
            for i in range(0, len(extracted_bits) - 7, 8):
                byte_bits = extracted_bits[i:i+8]
                if len(byte_bits) == 8:
                    byte_value = 0
                    for j, bit in enumerate(byte_bits):
                        byte_value |= (bit << (7 - j))
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