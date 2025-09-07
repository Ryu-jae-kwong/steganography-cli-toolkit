"""
PVD (Pixel Value Differencing) 스테가노그래피 알고리즘

PVD는 인접한 픽셀들 간의 차이값을 이용하여 데이터를 은닉하는 기법입니다.
차이값이 큰 영역(텍스처가 복잡한 부분)에 더 많은 데이터를 숨길 수 있어
시각적 품질을 유지하면서도 높은 은닉 용량을 제공합니다.

Reference: Wu & Tsai (2003), "A steganographic method for images by pixel-value differencing"
"""

import numpy as np
from PIL import Image
from typing import Optional, Tuple, List
import struct
import logging
from ..utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class PVDSteganography:
    """PVD (Pixel Value Differencing) 스테가노그래피 구현"""
    
    def __init__(self):
        # PVD 범위 테이블 (Wu & Tsai의 원본 범위)
        self.ranges = [
            (0, 7, 3),      # 차이값 0-7: 3비트
            (8, 15, 3),     # 차이값 8-15: 3비트  
            (16, 31, 4),    # 차이값 16-31: 4비트
            (32, 63, 5),    # 차이값 32-63: 5비트
            (64, 127, 6),   # 차이값 64-127: 6비트
            (128, 255, 7)   # 차이값 128-255: 7비트
        ]
    
    def _get_embeddable_bits(self, diff: int) -> int:
        """차이값에 따른 임베딩 가능한 비트 수 반환"""
        for lower, upper, bits in self.ranges:
            if lower <= diff <= upper:
                return bits
        return 0
    
    def _embed_in_pair(self, pixel1: int, pixel2: int, data_bits: str) -> Tuple[int, int]:
        """픽셀 쌍에 데이터 비트 임베딩"""
        if len(data_bits) == 0:
            return pixel1, pixel2
            
        diff = abs(pixel1 - pixel2)
        embeddable_bits = self._get_embeddable_bits(diff)
        
        if embeddable_bits == 0 or len(data_bits) < embeddable_bits:
            return pixel1, pixel2
            
        # 임베딩할 비트 추출
        embed_bits = data_bits[:embeddable_bits]
        embed_value = int(embed_bits, 2)
        
        # 새로운 차이값 계산
        for lower, upper, bits in self.ranges:
            if bits == embeddable_bits:
                new_diff = lower + embed_value
                break
        
        # 픽셀 값 조정
        if pixel1 >= pixel2:
            if pixel1 - new_diff >= 0:
                new_pixel1 = pixel1
                new_pixel2 = pixel1 - new_diff
            else:
                new_pixel1 = new_diff
                new_pixel2 = 0
        else:
            if pixel2 + new_diff <= 255:
                new_pixel1 = pixel1
                new_pixel2 = pixel1 + new_diff
            else:
                new_pixel1 = 255 - new_diff
                new_pixel2 = 255
                
        # 오버플로우/언더플로우 체크
        new_pixel1 = max(0, min(255, new_pixel1))
        new_pixel2 = max(0, min(255, new_pixel2))
        
        return new_pixel1, new_pixel2
    
    def _extract_from_pair(self, pixel1: int, pixel2: int) -> str:
        """픽셀 쌍에서 데이터 비트 추출"""
        diff = abs(pixel1 - pixel2)
        embeddable_bits = self._get_embeddable_bits(diff)
        
        if embeddable_bits == 0:
            return ""
            
        # 해당 범위에서의 상대적 위치 계산
        for lower, upper, bits in self.ranges:
            if lower <= diff <= upper and bits == embeddable_bits:
                relative_value = diff - lower
                return format(relative_value, f'0{bits}b')
        
        return ""
    
    def embed_message(self, input_path: str, message: str, output_path: str, 
                     password: Optional[str] = None) -> bool:
        """PVD 방법으로 메시지 임베딩"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 메시지 암호화 (필요시)
            if password:
                encrypted_data = encrypt_message(message.encode('utf-8'), password)
                message_bits = ''.join(format(byte, '08b') for byte in encrypted_data)
            else:
                message_bytes = message.encode('utf-8')
                message_bits = ''.join(format(byte, '08b') for byte in message_bytes)
            
            # 메시지 길이 정보 추가 (32비트)
            length_bits = format(len(message_bits), '032b')
            total_bits = length_bits + message_bits
            
            logger.info(f"임베딩할 총 비트 수: {len(total_bits)}")
            
            # 용량 체크
            max_capacity = self._calculate_capacity(img_array)
            if len(total_bits) > max_capacity:
                logger.error(f"메시지가 너무 큽니다. 최대 {max_capacity}비트, 요청 {len(total_bits)}비트")
                return False
            
            # PVD 임베딩
            new_img_array = img_array.copy()
            bit_index = 0
            
            for channel in range(channels):
                for row in range(height):
                    for col in range(0, width-1, 2):  # 2픽셀씩 쌍으로 처리
                        if bit_index >= len(total_bits):
                            break
                            
                        pixel1 = new_img_array[row, col, channel]
                        pixel2 = new_img_array[row, col+1, channel]
                        
                        # 임베딩 가능한 비트 수 확인
                        diff = abs(pixel1 - pixel2)
                        embeddable_bits = self._get_embeddable_bits(diff)
                        
                        if embeddable_bits > 0:
                            remaining_bits = len(total_bits) - bit_index
                            embed_count = min(embeddable_bits, remaining_bits)
                            
                            if embed_count > 0:
                                embed_data = total_bits[bit_index:bit_index + embed_count]
                                # 필요한 경우 비트 패딩
                                if len(embed_data) < embeddable_bits:
                                    embed_data = embed_data.ljust(embeddable_bits, '0')
                                
                                new_pixel1, new_pixel2 = self._embed_in_pair(
                                    pixel1, pixel2, embed_data
                                )
                                
                                new_img_array[row, col, channel] = new_pixel1
                                new_img_array[row, col+1, channel] = new_pixel2
                                
                                bit_index += embed_count
                    
                    if bit_index >= len(total_bits):
                        break
                
                if bit_index >= len(total_bits):
                    break
            
            # 결과 이미지 저장
            result_image = Image.fromarray(new_img_array.astype(np.uint8))
            result_image.save(output_path)
            
            logger.info(f"PVD 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"PVD 임베딩 실패: {e}")
            return False
    
    def extract_message(self, input_path: str, password: Optional[str] = None) -> Optional[str]:
        """PVD 방법으로 메시지 추출"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 메시지 길이 추출 (처음 32비트)
            extracted_bits = ""
            bit_count = 0
            
            for channel in range(channels):
                for row in range(height):
                    for col in range(0, width-1, 2):
                        if bit_count >= 32:
                            break
                            
                        pixel1 = img_array[row, col, channel]
                        pixel2 = img_array[row, col+1, channel]
                        
                        bits = self._extract_from_pair(pixel1, pixel2)
                        if bits:
                            needed_bits = min(len(bits), 32 - bit_count)
                            extracted_bits += bits[:needed_bits]
                            bit_count += needed_bits
                    
                    if bit_count >= 32:
                        break
                
                if bit_count >= 32:
                    break
            
            if len(extracted_bits) < 32:
                logger.error("메시지 길이 정보를 읽을 수 없습니다")
                return None
            
            message_length = int(extracted_bits[:32], 2)
            logger.info(f"메시지 길이: {message_length} 비트")
            
            if message_length <= 0 or message_length > 1000000:  # 1MB 제한
                logger.error("유효하지 않은 메시지 길이")
                return None
            
            # 실제 메시지 추출
            extracted_bits = ""
            bit_count = 0
            skip_length = 32  # 길이 정보 건너뛰기
            
            for channel in range(channels):
                for row in range(height):
                    for col in range(0, width-1, 2):
                        pixel1 = img_array[row, col, channel]
                        pixel2 = img_array[row, col+1, channel]
                        
                        bits = self._extract_from_pair(pixel1, pixel2)
                        if bits:
                            if skip_length > 0:
                                # 길이 정보 건너뛰기
                                if len(bits) <= skip_length:
                                    skip_length -= len(bits)
                                    continue
                                else:
                                    bits = bits[skip_length:]
                                    skip_length = 0
                            
                            # 메시지 비트 수집
                            needed_bits = min(len(bits), message_length - bit_count)
                            extracted_bits += bits[:needed_bits]
                            bit_count += needed_bits
                            
                            if bit_count >= message_length:
                                break
                    
                    if bit_count >= message_length:
                        break
                
                if bit_count >= message_length:
                    break
            
            # 비트를 바이트로 변환
            if len(extracted_bits) % 8 != 0:
                extracted_bits = extracted_bits.ljust(
                    ((len(extracted_bits) + 7) // 8) * 8, '0'
                )
            
            message_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                byte = extracted_bits[i:i+8]
                if len(byte) == 8:
                    message_bytes.append(int(byte, 2))
            
            # 복호화 (필요시)
            if password:
                decrypted_data = decrypt_message(bytes(message_bytes), password)
                return decrypted_data.decode('utf-8', errors='ignore')
            else:
                return bytes(message_bytes).decode('utf-8', errors='ignore')
                
        except Exception as e:
            logger.error(f"PVD 추출 실패: {e}")
            return None
    
    def _calculate_capacity(self, img_array: np.ndarray) -> int:
        """PVD 방법의 최대 임베딩 용량 계산"""
        height, width, channels = img_array.shape
        total_capacity = 0
        
        for channel in range(channels):
            for row in range(height):
                for col in range(0, width-1, 2):
                    pixel1 = img_array[row, col, channel]
                    pixel2 = img_array[row, col+1, channel]
                    
                    diff = abs(pixel1 - pixel2)
                    embeddable_bits = self._get_embeddable_bits(diff)
                    total_capacity += embeddable_bits
        
        return total_capacity
    
    def get_capacity(self, image_path: str) -> int:
        """이미지의 PVD 임베딩 용량 반환 (바이트 단위)"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            bit_capacity = self._calculate_capacity(img_array)
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, bit_capacity - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_image_suitability(self, image_path: str) -> dict:
        """이미지의 PVD 적합성 분석"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 차이값 분포 분석
            diff_distribution = {range_info[2]: 0 for range_info in self.ranges}
            total_pairs = 0
            
            for channel in range(channels):
                for row in range(height):
                    for col in range(0, width-1, 2):
                        pixel1 = img_array[row, col, channel]
                        pixel2 = img_array[row, col+1, channel]
                        
                        diff = abs(pixel1 - pixel2)
                        embeddable_bits = self._get_embeddable_bits(diff)
                        
                        if embeddable_bits > 0:
                            diff_distribution[embeddable_bits] += 1
                        
                        total_pairs += 1
            
            # 적합성 점수 계산 (높은 차이값 영역이 많을수록 좋음)
            suitability_score = sum(
                count * bits for bits, count in diff_distribution.items()
            ) / (total_pairs * 7)  # 7은 최대 비트 수
            
            return {
                'total_pairs': total_pairs,
                'diff_distribution': diff_distribution,
                'capacity_bytes': self.get_capacity(image_path),
                'suitability_score': suitability_score,
                'recommendation': 'Excellent' if suitability_score > 0.6 else
                                'Good' if suitability_score > 0.4 else
                                'Fair' if suitability_score > 0.2 else 'Poor'
            }
            
        except Exception as e:
            logger.error(f"적합성 분석 실패: {e}")
            return {}