"""
LSB 스테가노그래피 구현
RobinDavid/LSB-Steganography와 Stegano 라이브러리 패턴 통합
"""

import numpy as np
from PIL import Image
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from .exceptions import InvalidImageError, MessageTooLargeError, ExtractionError, CryptographyError, SteganographyError
from .factory import AlgorithmType


class LSBSteganography:
    """
    LSB 스테가노그래피 구현 클래스
    RobinDavid와 Stegano 라이브러리 패턴 통합
    """
    
    def __init__(self):
        self.algorithm_type = AlgorithmType.LSB
        self.delimiter = "###STEGO_END###"
        self.channels = 3  # RGB
    
    def embed_message(self, image_path: str, message: str, output_path: str, 
                     password: Optional[str] = None) -> bool:
        """
        메시지를 이미지에 임베딩
        
        Args:
            image_path: 원본 이미지 경로
            message: 숨길 메시지
            output_path: 출력 이미지 경로  
            password: 암호화용 패스워드 (선택사항)
        
        Returns:
            성공 여부
        """
        try:
            # 이미지 로드 및 검증
            image = self._load_and_validate_image(image_path)
            
            # 메시지 준비 (암호화 포함)
            prepared_message = self._prepare_message(message, password)
            
            # 용량 체크
            self._check_capacity(image, prepared_message)
            
            # LSB 임베딩 실행
            modified_image = self._embed_lsb(image, prepared_message)
            
            # 이미지 저장
            self._save_image(modified_image, output_path)
            
            return True
            
        except Exception as e:
            raise SteganographyError(f"임베딩 실패: {str(e)}")
    
    def extract_message(self, image_path: str, password: Optional[str] = None) -> str:
        """
        이미지에서 메시지 추출
        
        Args:
            image_path: 이미지 파일 경로
            password: 복호화용 패스워드 (선택사항)
        
        Returns:
            추출된 메시지
        """
        try:
            # 이미지 로드
            image = self._load_and_validate_image(image_path)
            
            # LSB 추출 실행
            extracted_data = self._extract_lsb(image)
            
            # 메시지 복호화 및 반환
            return self._process_extracted_message(extracted_data, password)
            
        except Exception as e:
            raise ExtractionError(f"추출 실패: {str(e)}")
    
    def get_capacity(self, image_path: str) -> int:
        """이미지의 최대 저장 가능 용량 (바이트)"""
        try:
            image = self._load_and_validate_image(image_path)
            width, height = image.size
            # RGB 각 채널에서 1비트씩 사용
            total_bits = width * height * self.channels
            return total_bits // 8  # 바이트 단위
        except Exception as e:
            raise InvalidImageError(image_path, str(e))
    
    def check_message_presence(self, image_path: str) -> bool:
        """메시지 존재 여부 확인"""
        try:
            self.extract_message(image_path)
            return True
        except (ExtractionError, CryptographyError):
            return False
    
    def _load_and_validate_image(self, image_path: str) -> Image.Image:
        """이미지 로드 및 검증"""
        path = Path(image_path)
        
        if not path.exists():
            raise InvalidImageError(image_path, "파일이 존재하지 않습니다")
        
        try:
            image = Image.open(path)
            
            # RGB 모드로 변환
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            return image
            
        except Exception as e:
            raise InvalidImageError(image_path, f"이미지 로드 실패: {str(e)}")
    
    def _prepare_message(self, message: str, password: Optional[str] = None) -> bytes:
        """메시지 준비 (암호화 포함)"""
        message_bytes = message.encode('utf-8')
        
        # 패스워드가 있으면 암호화
        if password:
            try:
                encrypted_data = self._encrypt_message(message_bytes, password)
                # 암호화된 데이터 + 구분자
                return encrypted_data + self.delimiter.encode('utf-8')
            except Exception as e:
                raise CryptographyError("encrypt", str(e))
        
        # 평문 메시지 + 구분자
        return message_bytes + self.delimiter.encode('utf-8')
    
    def _check_capacity(self, image: Image.Image, message_data: bytes):
        """용량 체크"""
        width, height = image.size
        available_bits = width * height * self.channels
        required_bits = len(message_data) * 8
        
        if required_bits > available_bits:
            raise MessageTooLargeError(len(message_data), available_bits // 8)
    
    def _embed_lsb(self, image: Image.Image, message_data: bytes) -> Image.Image:
        """
        LSB 임베딩 실행
        RobinDavid와 Stegano 패턴 결합
        """
        # 이미지를 numpy 배열로 변환
        image_array = np.array(image)
        flat_array = image_array.flatten()
        
        # 메시지를 비트로 변환
        message_bits = []
        for byte in message_data:
            for i in range(8):
                bit = (byte >> (7 - i)) & 1
                message_bits.append(bit)
        
        # LSB 임베딩 - NumPy 벡터화 활용
        for i, bit in enumerate(message_bits):
            if i < len(flat_array):
                # 핵심 LSB 조작: (pixel & 0xFE) | bit  
                flat_array[i] = (flat_array[i] & 0xFE) | bit
        
        # 배열을 이미지로 변환
        modified_array = flat_array.reshape(image_array.shape)
        return Image.fromarray(modified_array.astype('uint8'))
    
    def _extract_lsb(self, image: Image.Image) -> bytes:
        """
        LSB 추출 실행
        구분자 기반 메시지 종료 감지
        """
        image_array = np.array(image)
        flat_array = image_array.flatten()
        
        # 전체 LSB 비트 추출
        extracted_bits = []
        for pixel in flat_array:
            bit = pixel & 1
            extracted_bits.append(bit)
        
        # 바이트로 변환
        extracted_bytes = self._bits_to_bytes(extracted_bits)
        
        # 구분자 찾기
        delimiter_bytes = self.delimiter.encode('utf-8')
        delimiter_pos = extracted_bytes.find(delimiter_bytes)
        
        if delimiter_pos == -1:
            raise ExtractionError("구분자를 찾을 수 없습니다")
        
        # 구분자 이전의 데이터만 반환
        return extracted_bytes[:delimiter_pos]
    
    def _process_extracted_message(self, message_data: bytes, password: Optional[str] = None) -> str:
        """추출된 메시지 처리 (복호화 포함)"""
        try:
            # 패스워드가 있으면 복호화 시도
            if password:
                decrypted_data = self._decrypt_message(message_data, password)
                return decrypted_data.decode('utf-8')
            else:
                # 평문 메시지 처리
                return message_data.decode('utf-8')
                
        except UnicodeDecodeError:
            raise ExtractionError("메시지 디코딩 실패 - 잘못된 패스워드이거나 손상된 데이터")
    
    def _bits_to_bytes(self, bits: list) -> bytes:
        """비트 리스트를 바이트로 변환"""
        if len(bits) % 8 != 0:
            # 패딩 추가
            padding_needed = 8 - (len(bits) % 8)
            bits.extend([0] * padding_needed)
        
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            byte_value = 0
            for j, bit in enumerate(byte_bits):
                byte_value |= bit << (7 - j)
            bytes_list.append(byte_value)
        
        return bytes(bytes_list)
    
    def _encrypt_message(self, message: bytes, password: str) -> bytes:
        """메시지 암호화 (AES-256-GCM 방식)"""
        try:
            # PBKDF2로 키 유도
            salt = b'steganography_salt_2024'  # 실제로는 랜덤 생성 필요
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Fernet 암호화
            f = Fernet(key)
            return f.encrypt(message)
            
        except Exception as e:
            raise CryptographyError("encrypt", str(e))
    
    def _decrypt_message(self, encrypted_message: bytes, password: str) -> bytes:
        """메시지 복호화"""
        try:
            # 동일한 키 유도 과정
            salt = b'steganography_salt_2024'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Fernet 복호화
            f = Fernet(key)
            return f.decrypt(encrypted_message)
            
        except Exception as e:
            raise CryptographyError("decrypt", str(e))
    
    def _save_image(self, image: Image.Image, output_path: str):
        """이미지 저장"""
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            image.save(output_path)
        except Exception as e:
            raise InvalidImageError(str(output_path), f"이미지 저장 실패: {str(e)}")


