"""
F5 스테가노그래피 알고리즘 (간단한 구현)
JPEG DCT 계수를 사용한 고급 스테가노그래피
"""

import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct
import skimage.util
from typing import Optional

from .exceptions import SteganographyError


# JPEG 표준 양자화 테이블
QUANTIZATION_TABLE = np.array([
    [16, 11, 10, 16, 24, 40, 51, 61],
    [12, 12, 14, 19, 26, 58, 60, 55],
    [14, 13, 16, 24, 40, 57, 69, 56],
    [14, 17, 22, 29, 51, 87, 80, 62],
    [18, 22, 37, 56, 68, 109, 103, 77],
    [24, 35, 55, 64, 81, 104, 113, 92],
    [49, 64, 78, 87, 103, 121, 120, 101],
    [72, 92, 95, 98, 112, 100, 103, 99]
], dtype=np.float32)


def dct2(block):
    """2D DCT 변환"""
    return dct(dct(block.T, norm='ortho').T, norm='ortho')


def idct2(block):
    """2D 역 DCT 변환"""  
    return idct(idct(block.T, norm='ortho').T, norm='ortho')


def f5_embed_bit(coeff, bit):
    """F5 방식 비트 임베딩 (계수값이 0이 되지 않도록)"""
    if coeff == 0:
        return 0  # 0인 계수는 건드리지 않음
    
    if coeff > 0:
        if coeff % 2 != bit:
            coeff -= 1
            if coeff == 0:
                coeff = 1  # 0이 되지 않도록 조정
    else:  # coeff < 0
        if (-coeff) % 2 != bit:
            coeff += 1
            if coeff == 0:
                coeff = -1  # 0이 되지 않도록 조정
    
    return coeff


def f5_extract_bit(coeff):
    """F5 방식 비트 추출"""
    if coeff == 0:
        return 0
    elif coeff > 0:
        return coeff % 2
    else:
        return (-coeff) % 2


class F5Steganography:
    """F5 알고리즘 구현 (간단한 버전)"""
    
    def __init__(self):
        self.delimiter = "###STEGO_END###"  # F5용 구분자
    
    def get_capacity(self, image_path: str) -> int:
        """F5 알고리즘으로 숨길 수 있는 최대 용량 계산"""
        try:
            image = Image.open(image_path).convert('RGB')
            width, height = image.size
            
            # 8x8 블록 개수
            blocks_w = width // 8
            blocks_h = height // 8
            total_blocks = blocks_w * blocks_h
            
            # F5는 0이 아닌 AC 계수만 사용
            # 보수적으로 블록당 15개 계수 추정
            usable_coeffs_per_block = 15
            
            capacity_bits = total_blocks * usable_coeffs_per_block
            return capacity_bits // 8
            
        except Exception as e:
            raise SteganographyError(f"용량 계산 실패: {e}")
    
    def check_message_presence(self, image_path: str) -> bool:
        """메시지 존재 여부 확인"""
        try:
            image = Image.open(image_path).convert('RGB')
            blue_channel = np.array(image)[:, :, 2]
            
            # 첫 번째 8x8 블록 확인
            if blue_channel.shape[0] >= 8 and blue_channel.shape[1] >= 8:
                block = blue_channel[:8, :8].astype(np.float32) - 128
                dct_block = dct2(block)
                quantized = np.round(dct_block / QUANTIZATION_TABLE)
                
                # 0이 아닌 AC 계수들의 패턴 확인
                non_zero_count = np.count_nonzero(quantized[1:, 1:])
                return non_zero_count > 5  # 최소한의 변화 감지
            
            return False
            
        except Exception:
            return False
    
    def embed_message(self, image_path: str, message: str, output_path: str, password: Optional[str] = None) -> bool:
        """F5 방식으로 메시지 임베딩"""
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
                for bit in format(byte, '08b'):
                    message_bits.append(int(bit))
            
            # 8x8 블록으로 분할
            h, w = blue_channel.shape
            blocks_h = h // 8
            blocks_w = w // 8
            
            bit_index = 0
            
            for i in range(blocks_h):
                for j in range(blocks_w):
                    if bit_index >= len(message_bits):
                        break
                    
                    # 8x8 블록 추출
                    block = blue_channel[i*8:(i+1)*8, j*8:(j+1)*8] - 128
                    
                    # DCT 변환
                    dct_block = dct2(block)
                    
                    # 양자화
                    quantized = np.round(dct_block / QUANTIZATION_TABLE)
                    
                    # F5 방식으로 0이 아닌 AC 계수에만 임베딩
                    # 지그재그 스캔 순서
                    zigzag_positions = [
                        (0,1), (1,0), (0,2), (1,1), (2,0), (0,3), (1,2), (2,1), (3,0),
                        (0,4), (1,3), (2,2), (3,1), (4,0), (0,5), (1,4), (2,3), (3,2), (4,1), (5,0)
                    ]
                    
                    for pos in zigzag_positions:
                        if bit_index >= len(message_bits):
                            break
                        
                        row, col = pos
                        if row < 8 and col < 8 and quantized[row, col] != 0:
                            quantized[row, col] = f5_embed_bit(
                                quantized[row, col], message_bits[bit_index]
                            )
                            bit_index += 1
                    
                    # 역양자화 및 역 DCT
                    dequantized = quantized * QUANTIZATION_TABLE
                    restored_block = idct2(dequantized) + 128
                    
                    # 블록을 다시 이미지에 삽입
                    blue_channel[i*8:(i+1)*8, j*8:(j+1)*8] = np.clip(restored_block, 0, 255)
                
                if bit_index >= len(message_bits):
                    break
            
            # 결과 이미지 저장
            img_array[:, :, 2] = blue_channel.astype(np.uint8)
            result_image = Image.fromarray(img_array.astype(np.uint8))
            result_image.save(output_path)
            
            return True
            
        except Exception as e:
            raise SteganographyError(f"F5 임베딩 실패: {e}")
    
    def extract_message(self, image_path: str, password: Optional[str] = None) -> str:
        """F5 방식으로 메시지 추출"""
        try:
            # 이미지 로드
            image = Image.open(image_path).convert('RGB')
            img_array = np.array(image)
            blue_channel = img_array[:, :, 2].astype(np.float32)
            
            # 8x8 블록으로 분할
            h, w = blue_channel.shape
            blocks_h = h // 8
            blocks_w = w // 8
            
            extracted_bits = []
            
            # 충분한 데이터를 얻을 때까지 블록 처리
            max_bits_needed = 2000
            
            for i in range(blocks_h):
                for j in range(blocks_w):
                    if len(extracted_bits) >= max_bits_needed:
                        break
                        
                    # 8x8 블록 추출
                    block = blue_channel[i*8:(i+1)*8, j*8:(j+1)*8] - 128
                    
                    # DCT 변환
                    dct_block = dct2(block)
                    
                    # 양자화
                    quantized = np.round(dct_block / QUANTIZATION_TABLE)
                    
                    # F5 방식으로 0이 아닌 AC 계수에서 비트 추출 - 임베딩과 동일한 위치
                    zigzag_positions = [
                        (0,1), (1,0), (0,2), (1,1), (2,0), (0,3), (1,2), (2,1), (3,0),
                        (0,4), (1,3), (2,2), (3,1), (4,0), (0,5), (1,4), (2,3), (3,2), (4,1), (5,0)
                    ]
                    
                    for pos in zigzag_positions:
                        if len(extracted_bits) >= max_bits_needed:
                            break
                        row, col = pos
                        if row < 8 and col < 8 and quantized[row, col] != 0:
                            bit = f5_extract_bit(quantized[row, col])
                            extracted_bits.append(int(bit))
                
                if len(extracted_bits) >= max_bits_needed:
                    break
            
            # 비트를 바이트로 변환
            message_bytes = bytearray()
            for i in range(0, len(extracted_bits) - 7, 8):
                byte_bits = extracted_bits[i:i+8]
                if len(byte_bits) == 8:
                    byte_value = 0
                    for j, bit in enumerate(byte_bits):
                        byte_value |= (int(bit) << (7 - j))
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
            raise SteganographyError(f"F5 추출 실패: {e}")
    
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