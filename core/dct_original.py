"""
DCT (Discrete Cosine Transform) 스테가노그래피 알고리즘
JPEG 압축과 유사한 주파수 도메인 기법
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


def embed_bit_in_coeff(coeff, bit):
    """DCT 계수에 비트 임베딩 (F5 방식)"""
    coeff_int = int(coeff)
    if coeff_int > 0:
        if coeff_int % 2 != bit:
            coeff_int -= 1
        if coeff_int == 0:
            coeff_int = 1
    elif coeff_int < 0:
        if (-coeff_int) % 2 != bit:
            coeff_int += 1
        if coeff_int == 0:
            coeff_int = -1
    return coeff_int


def extract_bit_from_coeff(coeff):
    """DCT 계수에서 비트 추출"""
    coeff_int = int(coeff)
    if coeff_int > 0:
        return coeff_int % 2
    else:
        return (-coeff_int) % 2


class DCTSteganography:
    """DCT 기반 스테가노그래피 구현"""
    
    def __init__(self):
        self.delimiter = "###STEGO_END###"  # DCT용 구분자
    
    def get_capacity(self, image_path: str) -> int:
        """DCT 알고리즘으로 숨길 수 있는 최대 용량 계산"""
        try:
            image = Image.open(image_path).convert('RGB')
            width, height = image.size
            
            # 8x8 블록 개수 계산
            blocks_w = width // 8
            blocks_h = height // 8
            total_blocks = blocks_w * blocks_h
            
            # 각 블록에서 사용 가능한 AC 계수 (DC 제외한 63개 중 사용 가능한 것들)
            usable_coeffs_per_block = 20  # 보수적 추정
            
            # 비트 단위 용량을 바이트로 변환
            capacity_bits = total_blocks * usable_coeffs_per_block
            return capacity_bits // 8
            
        except Exception as e:
            raise SteganographyError(f"용량 계산 실패: {e}")
    
    def check_message_presence(self, image_path: str) -> bool:
        """메시지 존재 여부 확인"""
        try:
            image = Image.open(image_path).convert('RGB')
            blue_channel = np.array(image)[:, :, 2]
            
            # 8x8 블록으로 분할 가능한지 확인
            h, w = blue_channel.shape
            if h < 8 or w < 8:
                return False
            
            # 첫 번째 블록에서 DCT 수행
            first_block = blue_channel[:8, :8].astype(np.float32) - 128
            dct_block = dct2(first_block)
            quantized = np.round(dct_block / QUANTIZATION_TABLE)
            
            # AC 계수들 확인
            ac_coeffs = quantized[0, 1:4]  # 일부 AC 계수
            if np.any(ac_coeffs != 0):
                return True
            
            return False
            
        except Exception:
            return False
    
    def embed_message(self, image_path: str, message: str, output_path: str, password: Optional[str] = None) -> bool:
        """DCT 방식으로 메시지 임베딩"""
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
            
            # 8x8 블록으로 분할
            h, w = blue_channel.shape
            blocks_h = h // 8
            blocks_w = w // 8
            
            if len(message_bits) > blocks_h * blocks_w * 20:  # 용량 체크
                raise SteganographyError("메시지가 너무 큽니다")
            
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
                    
                    # AC 계수에 메시지 비트 임베딩
                    # 지그재그 패턴으로 AC 계수 선택
                    positions = [(0,1), (1,0), (0,2), (1,1), (2,0)]
                    
                    for pos in positions:
                        if bit_index >= len(message_bits):
                            break
                        
                        row, col = pos
                        if row < 8 and col < 8:
                            quantized[row, col] = embed_bit_in_coeff(
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
            raise SteganographyError(f"DCT 임베딩 실패: {e}")
    
    def extract_message(self, image_path: str, password: Optional[str] = None) -> str:
        """DCT 방식으로 메시지 추출"""
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
            max_bits_needed = 2000  # 충분한 비트 확보
            
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
                    
                    # AC 계수에서 비트 추출 - 임베딩과 동일한 위치 사용
                    positions = [(0,1), (1,0), (0,2), (1,1), (2,0)]
                    
                    for pos in positions:
                        if len(extracted_bits) >= max_bits_needed:
                            break
                        row, col = pos
                        if row < 8 and col < 8:
                            bit = extract_bit_from_coeff(quantized[row, col])
                            extracted_bits.append(bit)
                
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
            
            # 구분자로 메시지 분리
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
            raise SteganographyError(f"DCT 추출 실패: {e}")
    
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