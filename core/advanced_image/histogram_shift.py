"""
Histogram Shifting 스테가노그래피 알고리즘

히스토그램 시프팅은 이미지의 픽셀 값 히스토그램을 조작하여 데이터를 은닉하는 기법입니다.
특정 픽셀 값의 빈도를 이동(shift)시켜서 빈 공간을 만들고, 
그 공간을 이용해 데이터를 임베딩합니다. 가역적(reversible) 스테가노그래피의 대표적인 방법입니다.

Reference: Ni et al. (2006), "Reversible data hiding"
"""

import numpy as np
from PIL import Image
from typing import Optional, List, Tuple, Dict
import logging
from collections import Counter
from ..utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class HistogramShiftSteganography:
    """Histogram Shifting 스테가노그래피 구현"""
    
    def __init__(self):
        self.peak_value = None      # 히스토그램에서 가장 높은 빈도의 픽셀 값
        self.zero_value = None      # 빈도가 0인 픽셀 값
        self.shift_direction = 1    # 시프트 방향 (1: 오른쪽, -1: 왼쪽)
    
    def _analyze_histogram(self, image_array: np.ndarray, channel: int = 0) -> Dict:
        """히스토그램 분석 및 최적의 peak/zero 값 찾기"""
        if len(image_array.shape) == 3:
            pixel_values = image_array[:, :, channel].flatten()
        else:
            pixel_values = image_array.flatten()
        
        # 히스토그램 계산
        histogram = Counter(pixel_values)
        
        # 가장 높은 빈도의 픽셀 값 찾기 (peak)
        peak_value = max(histogram.items(), key=lambda x: x[1])[0]
        peak_count = histogram[peak_value]
        
        # 빈도가 0인 픽셀 값 찾기 (zero point)
        zero_values = []
        for val in range(256):
            if val not in histogram:
                zero_values.append(val)
        
        # peak 근처의 zero point 선택
        if zero_values:
            zero_value = min(zero_values, key=lambda x: abs(x - peak_value))
        else:
            # 빈도가 가장 낮은 값을 zero point로 사용
            zero_value = min(histogram.items(), key=lambda x: x[1])[0]
        
        # 시프트 방향 결정
        if zero_value > peak_value:
            shift_direction = 1  # 오른쪽으로 시프트
            shift_range = list(range(peak_value + 1, zero_value + 1))
        else:
            shift_direction = -1  # 왼쪽으로 시프트
            shift_range = list(range(zero_value, peak_value))
        
        return {
            'histogram': histogram,
            'peak_value': peak_value,
            'peak_count': peak_count,
            'zero_value': zero_value,
            'shift_direction': shift_direction,
            'shift_range': shift_range,
            'capacity': peak_count  # peak_value 픽셀 수만큼 임베딩 가능
        }
    
    def _apply_histogram_shift(self, image_array: np.ndarray, analysis: Dict, 
                              channel: int = 0) -> np.ndarray:
        """히스토그램 시프트 적용 (데이터 임베딩을 위한 공간 확보)"""
        new_array = image_array.copy()
        
        peak_value = analysis['peak_value']
        shift_direction = analysis['shift_direction']
        shift_range = analysis['shift_range']
        
        if len(new_array.shape) == 3:
            channel_data = new_array[:, :, channel]
        else:
            channel_data = new_array
        
        # 시프트 범위의 픽셀들을 이동
        for shift_val in shift_range:
            if shift_direction > 0:
                # 오른쪽 시프트: shift_val을 shift_val + 1로
                channel_data[channel_data == shift_val] = shift_val + 1
            else:
                # 왼쪽 시프트: shift_val을 shift_val - 1로  
                channel_data[channel_data == shift_val] = shift_val - 1
        
        return new_array
    
    def _embed_data_in_peak(self, image_array: np.ndarray, data_bits: str, 
                           analysis: Dict, channel: int = 0) -> np.ndarray:
        """Peak 값에 데이터 임베딩"""
        new_array = image_array.copy()
        
        peak_value = analysis['peak_value']
        zero_value = analysis['zero_value']
        
        if len(new_array.shape) == 3:
            channel_data = new_array[:, :, channel]
        else:
            channel_data = new_array
        
        # Peak 값을 가진 픽셀 위치 찾기
        peak_positions = np.where(channel_data == peak_value)
        peak_count = len(peak_positions[0])
        
        # 임베딩할 데이터 길이 확인
        embed_length = min(len(data_bits), peak_count)
        
        # 데이터 임베딩
        for i in range(embed_length):
            row, col = peak_positions[0][i], peak_positions[1][i]
            bit = int(data_bits[i])
            
            if bit == 1:
                # 1을 임베딩: peak_value를 zero_value로 변경
                channel_data[row, col] = zero_value
            # 0을 임베딩: peak_value를 그대로 유지 (변경 없음)
        
        return new_array
    
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None, channel: int = 0) -> bool:
        """Histogram Shifting 방법으로 메시지 임베딩"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
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
            
            # 히스토그램 분석
            analysis = self._analyze_histogram(img_array, channel)
            
            logger.info(f"Peak value: {analysis['peak_value']}, count: {analysis['peak_count']}")
            logger.info(f"Zero value: {analysis['zero_value']}")
            
            # 용량 체크
            if len(total_bits) > analysis['capacity']:
                logger.error(f"메시지가 너무 큽니다. 최대 {analysis['capacity']}비트, 요청 {len(total_bits)}비트")
                return False
            
            # 히스토그램 시프트 적용
            shifted_array = self._apply_histogram_shift(img_array, analysis, channel)
            
            # 데이터 임베딩
            result_array = self._embed_data_in_peak(shifted_array, total_bits, analysis, channel)
            
            # 임베딩 메타데이터 저장 (복구를 위해)
            self.peak_value = analysis['peak_value']
            self.zero_value = analysis['zero_value'] 
            self.shift_direction = analysis['shift_direction']
            
            # 결과 이미지 저장
            result_image = Image.fromarray(result_array.astype(np.uint8))
            result_image.save(output_path)
            
            logger.info(f"Histogram Shifting 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Histogram Shifting 임베딩 실패: {e}")
            return False
    
    def extract_message(self, input_path: str, password: Optional[str] = None, 
                       channel: int = 0) -> Optional[str]:
        """Histogram Shifting 방법으로 메시지 추출"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # 현재 히스토그램 분석 (임베딩된 상태)
            current_analysis = self._analyze_histogram(img_array, channel)
            
            # 원본 peak/zero 값 추정 (임베딩 시와 동일해야 함)
            if self.peak_value is not None and self.zero_value is not None:
                peak_value = self.peak_value
                zero_value = self.zero_value
            else:
                # 메타데이터가 없는 경우 추정
                peak_value = current_analysis['peak_value']
                # zero_value는 히스토그램에서 빈도가 가장 높은 두 번째 값으로 추정
                histogram = current_analysis['histogram']
                sorted_values = sorted(histogram.items(), key=lambda x: x[1], reverse=True)
                zero_value = sorted_values[1][0] if len(sorted_values) > 1 else peak_value + 1
            
            logger.info(f"추출에 사용할 Peak value: {peak_value}, Zero value: {zero_value}")
            
            if len(img_array.shape) == 3:
                channel_data = img_array[:, :, channel]
            else:
                channel_data = img_array
            
            # 데이터 추출
            extracted_bits = ""
            
            # peak_value와 zero_value 위치에서 비트 추출
            peak_positions = np.where(channel_data == peak_value)
            zero_positions = np.where(channel_data == zero_value)
            
            # 모든 관련 위치를 행-우선 순서로 정렬
            all_positions = []
            
            # Peak 위치 (0 비트)
            for i in range(len(peak_positions[0])):
                row, col = peak_positions[0][i], peak_positions[1][i]
                all_positions.append((row, col, '0'))
            
            # Zero 위치 (1 비트)  
            for i in range(len(zero_positions[0])):
                row, col = zero_positions[0][i], zero_positions[1][i]
                all_positions.append((row, col, '1'))
            
            # 행-우선 순서로 정렬
            all_positions.sort(key=lambda x: (x[0], x[1]))
            
            # 비트 추출
            for row, col, bit in all_positions:
                extracted_bits += bit
            
            # 메시지 길이 정보 추출
            if len(extracted_bits) < 32:
                logger.error("메시지 길이 정보를 읽을 수 없습니다")
                return None
            
            message_length = int(extracted_bits[:32], 2)
            logger.info(f"메시지 길이: {message_length} 비트")
            
            if message_length <= 0 or message_length > len(extracted_bits) - 32:
                logger.error("유효하지 않은 메시지 길이")
                return None
            
            # 실제 메시지 비트 추출
            message_bits = extracted_bits[32:32 + message_length]
            
            # 비트를 바이트로 변환
            if len(message_bits) % 8 != 0:
                message_bits = message_bits.ljust(
                    ((len(message_bits) + 7) // 8) * 8, '0'
                )
            
            message_bytes = bytearray()
            for i in range(0, len(message_bits), 8):
                byte = message_bits[i:i+8]
                if len(byte) == 8:
                    message_bytes.append(int(byte, 2))
            
            # 복호화 (필요시)
            if password:
                decrypted_data = decrypt_message(bytes(message_bytes), password)
                return decrypted_data.decode('utf-8', errors='ignore')
            else:
                return bytes(message_bytes).decode('utf-8', errors='ignore')
                
        except Exception as e:
            logger.error(f"Histogram Shifting 추출 실패: {e}")
            return None
    
    def get_capacity(self, image_path: str, channel: int = 0) -> int:
        """이미지의 Histogram Shifting 임베딩 용량 반환 (바이트 단위)"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # 히스토그램 분석
            analysis = self._analyze_histogram(img_array, channel)
            
            # Peak 값의 빈도가 임베딩 용량
            capacity_bits = analysis['capacity']
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, capacity_bits - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_histogram_characteristics(self, image_path: str, channel: int = 0) -> Dict:
        """히스토그램 특성 분석"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            analysis = self._analyze_histogram(img_array, channel)
            
            histogram = analysis['histogram']
            
            # 통계 계산
            total_pixels = np.sum(list(histogram.values()))
            unique_values = len(histogram)
            peak_ratio = analysis['peak_count'] / total_pixels
            
            # 히스토그램 분포 분석
            values = list(histogram.keys())
            counts = list(histogram.values())
            
            entropy = -np.sum([(c/total_pixels) * np.log2(c/total_pixels + 1e-8) for c in counts])
            
            return {
                'total_pixels': total_pixels,
                'unique_values': unique_values,
                'peak_value': analysis['peak_value'],
                'peak_count': analysis['peak_count'],
                'peak_ratio': peak_ratio,
                'zero_value': analysis['zero_value'],
                'capacity_bytes': self.get_capacity(image_path, channel),
                'histogram_entropy': entropy,
                'suitability': 'Excellent' if peak_ratio > 0.1 else
                             'Good' if peak_ratio > 0.05 else
                             'Fair' if peak_ratio > 0.02 else 'Poor'
            }
            
        except Exception as e:
            logger.error(f"히스토그램 특성 분석 실패: {e}")
            return {}
    
    def visualize_histogram(self, image_path: str, output_path: str, channel: int = 0) -> bool:
        """히스토그램 시각화"""
        try:
            import matplotlib.pyplot as plt
            
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            analysis = self._analyze_histogram(img_array, channel)
            
            histogram = analysis['histogram']
            
            # 히스토그램 플롯
            plt.figure(figsize=(12, 6))
            
            # 원본 히스토그램
            plt.subplot(1, 2, 1)
            values = list(range(256))
            counts = [histogram.get(v, 0) for v in values]
            
            plt.bar(values, counts, alpha=0.7, color='blue')
            plt.axvline(x=analysis['peak_value'], color='red', linestyle='--', 
                       label=f'Peak: {analysis["peak_value"]}')
            plt.axvline(x=analysis['zero_value'], color='green', linestyle='--', 
                       label=f'Zero: {analysis["zero_value"]}')
            plt.xlabel('Pixel Value')
            plt.ylabel('Frequency')
            plt.title('Original Histogram')
            plt.legend()
            
            # 시프트 후 히스토그램 시뮬레이션
            plt.subplot(1, 2, 2)
            shifted_histogram = histogram.copy()
            
            # 시프트 시뮬레이션
            for shift_val in analysis['shift_range']:
                if analysis['shift_direction'] > 0:
                    shifted_histogram[shift_val + 1] = shifted_histogram.pop(shift_val, 0)
                else:
                    shifted_histogram[shift_val - 1] = shifted_histogram.pop(shift_val, 0)
            
            shifted_counts = [shifted_histogram.get(v, 0) for v in values]
            plt.bar(values, shifted_counts, alpha=0.7, color='orange')
            plt.axvline(x=analysis['peak_value'], color='red', linestyle='--', 
                       label=f'Peak: {analysis["peak_value"]}')
            plt.axvline(x=analysis['zero_value'], color='green', linestyle='--', 
                       label=f'Zero: {analysis["zero_value"]}')
            plt.xlabel('Pixel Value')
            plt.ylabel('Frequency') 
            plt.title('After Histogram Shift')
            plt.legend()
            
            plt.tight_layout()
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"히스토그램 시각화 저장: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"히스토그램 시각화 실패: {e}")
            return False