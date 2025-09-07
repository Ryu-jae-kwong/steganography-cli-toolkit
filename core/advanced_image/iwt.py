"""
IWT (Integer Wavelet Transform) 스테가노그래피 알고리즘

IWT는 정수 웨이블릿 변환을 사용하여 데이터를 은닉하는 기법입니다.
웨이블릿 변환은 이미지를 주파수 도메인으로 변환하여 
고주파 영역에 데이터를 은닉함으로써 시각적 품질을 유지합니다.

Reference: Haar wavelet transform with integer implementation
"""

import numpy as np
from PIL import Image
from typing import Optional, Tuple, List
import logging
from ..utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class IWTSteganography:
    """IWT (Integer Wavelet Transform) 스테가노그래피 구현"""
    
    def __init__(self, wavelet_type: str = 'haar', decomposition_level: int = 1):
        """
        Args:
            wavelet_type: 웨이블릿 타입 (현재는 'haar'만 지원)
            decomposition_level: 분해 레벨 (기본값: 1)
        """
        self.wavelet_type = wavelet_type
        self.decomposition_level = decomposition_level
    
    def _haar_forward(self, data: np.ndarray) -> np.ndarray:
        """Haar 웨이블릿 순변환 (정수 연산)"""
        if len(data) % 2 != 0:
            # 홀수 길이인 경우 패딩
            data = np.append(data, data[-1])
        
        result = np.zeros_like(data)
        half_len = len(data) // 2
        
        # Low-pass (평균) 및 High-pass (차이) 계산
        for i in range(half_len):
            # 정수 연산으로 수행
            low = (data[2*i] + data[2*i+1]) // 2
            high = data[2*i] - data[2*i+1]
            
            result[i] = low
            result[half_len + i] = high
        
        return result
    
    def _haar_inverse(self, data: np.ndarray) -> np.ndarray:
        """Haar 웨이블릿 역변환 (정수 연산)"""
        result = np.zeros_like(data)
        half_len = len(data) // 2
        
        for i in range(half_len):
            low = data[i]
            high = data[half_len + i]
            
            # 역변환 공식
            result[2*i] = low + (high + 1) // 2
            result[2*i+1] = low - high // 2
        
        return result
    
    def _iwt_2d_forward(self, image_array: np.ndarray) -> np.ndarray:
        """2D IWT 순변환"""
        height, width = image_array.shape
        result = image_array.astype(np.int32).copy()
        
        # 행 방향 변환
        for i in range(height):
            result[i, :] = self._haar_forward(result[i, :])
        
        # 열 방향 변환
        for j in range(width):
            result[:, j] = self._haar_forward(result[:, j])
        
        return result
    
    def _iwt_2d_inverse(self, transformed: np.ndarray) -> np.ndarray:
        """2D IWT 역변환"""
        height, width = transformed.shape
        result = transformed.copy()
        
        # 열 방향 역변환
        for j in range(width):
            result[:, j] = self._haar_inverse(result[:, j])
        
        # 행 방향 역변환
        for i in range(height):
            result[i, :] = self._haar_inverse(result[i, :])
        
        return result
    
    def _get_high_frequency_positions(self, height: int, width: int) -> List[Tuple[int, int]]:
        """고주파 영역의 좌표 반환 (HH, HL, LH 대역)"""
        positions = []
        half_h, half_w = height // 2, width // 2
        
        # HH (대각선 고주파)
        for i in range(half_h, height):
            for j in range(half_w, width):
                positions.append((i, j))
        
        # HL (수평 고주파)
        for i in range(half_h):
            for j in range(half_w, width):
                positions.append((i, j))
        
        # LH (수직 고주파)
        for i in range(half_h, height):
            for j in range(half_w):
                positions.append((i, j))
        
        return positions
    
    def _select_embedding_positions(self, coefficients: np.ndarray, 
                                  capacity_needed: int) -> List[Tuple[int, int]]:
        """임베딩에 적합한 고주파 계수 위치 선택"""
        height, width = coefficients.shape
        high_freq_positions = self._get_high_frequency_positions(height, width)
        
        # 계수 크기 기준으로 정렬 (큰 계수일수록 우선)
        positions_with_magnitude = []
        for pos in high_freq_positions:
            magnitude = abs(coefficients[pos])
            if magnitude > 1:  # 최소 임계값
                positions_with_magnitude.append((magnitude, pos))
        
        # 크기 순으로 정렬
        positions_with_magnitude.sort(reverse=True)
        
        # 필요한 만큼만 선택
        selected_positions = []
        for magnitude, pos in positions_with_magnitude:
            if len(selected_positions) >= capacity_needed:
                break
            selected_positions.append(pos)
        
        return selected_positions
    
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None) -> bool:
        """IWT 방법으로 메시지 임베딩"""
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
            
            # 각 채널별로 임베딩
            new_img_array = img_array.copy()
            
            for channel in range(channels):
                # IWT 변환
                channel_data = img_array[:, :, channel].astype(np.int32)
                iwt_coefficients = self._iwt_2d_forward(channel_data)
                
                # 임베딩 위치 선택
                embedding_positions = self._select_embedding_positions(
                    iwt_coefficients, len(total_bits) // channels + 1
                )
                
                if not embedding_positions:
                    logger.error(f"채널 {channel}에서 임베딩 가능한 위치를 찾을 수 없습니다")
                    continue
                
                # LSB 임베딩 (고주파 계수에)
                bit_index = channel * (len(total_bits) // channels)
                end_index = min(bit_index + len(total_bits) // channels, len(total_bits))
                
                for pos_idx, (i, j) in enumerate(embedding_positions):
                    if bit_index >= len(total_bits) or bit_index >= end_index:
                        break
                    
                    # 계수값에 LSB 임베딩
                    coefficient = iwt_coefficients[i, j]
                    bit = int(total_bits[bit_index])
                    
                    # 계수의 LSB 수정
                    if coefficient >= 0:
                        new_coefficient = (coefficient & ~1) | bit
                    else:
                        # 음수의 경우 절댓값의 LSB 수정
                        abs_coeff = abs(coefficient)
                        new_abs_coeff = (abs_coeff & ~1) | bit
                        new_coefficient = -new_abs_coeff if coefficient < 0 else new_abs_coeff
                    
                    iwt_coefficients[i, j] = new_coefficient
                    bit_index += 1
                
                # IWT 역변환
                restored_channel = self._iwt_2d_inverse(iwt_coefficients)
                
                # 픽셀 값 범위 클리핑
                restored_channel = np.clip(restored_channel, 0, 255)
                new_img_array[:, :, channel] = restored_channel.astype(np.uint8)
            
            # 결과 이미지 저장
            result_image = Image.fromarray(new_img_array.astype(np.uint8))
            result_image.save(output_path)
            
            logger.info(f"IWT 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"IWT 임베딩 실패: {e}")
            return False
    
    def extract_message(self, input_path: str, password: Optional[str] = None) -> Optional[str]:
        """IWT 방법으로 메시지 추출"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 각 채널에서 비트 추출
            all_extracted_bits = ""
            
            for channel in range(channels):
                # IWT 변환
                channel_data = img_array[:, :, channel].astype(np.int32)
                iwt_coefficients = self._iwt_2d_forward(channel_data)
                
                # 고주파 영역 위치 획득
                high_freq_positions = self._get_high_frequency_positions(height, width)
                
                # 계수 크기 기준으로 정렬
                positions_with_magnitude = []
                for pos in high_freq_positions:
                    magnitude = abs(iwt_coefficients[pos])
                    if magnitude > 1:
                        positions_with_magnitude.append((magnitude, pos))
                
                positions_with_magnitude.sort(reverse=True)
                
                # 비트 추출
                for magnitude, (i, j) in positions_with_magnitude:
                    coefficient = iwt_coefficients[i, j]
                    bit = abs(coefficient) & 1
                    all_extracted_bits += str(bit)
            
            # 메시지 길이 추출
            if len(all_extracted_bits) < 32:
                logger.error("메시지 길이 정보를 읽을 수 없습니다")
                return None
            
            message_length = int(all_extracted_bits[:32], 2)
            logger.info(f"메시지 길이: {message_length} 비트")
            
            if message_length <= 0 or message_length > len(all_extracted_bits) - 32:
                logger.error("유효하지 않은 메시지 길이")
                return None
            
            # 실제 메시지 추출
            message_bits = all_extracted_bits[32:32 + message_length]
            
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
            logger.error(f"IWT 추출 실패: {e}")
            return None
    
    def get_capacity(self, image_path: str) -> int:
        """이미지의 IWT 임베딩 용량 반환 (바이트 단위)"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 고주파 영역 계산
            high_freq_positions = self._get_high_frequency_positions(height, width)
            
            # 각 채널의 용량 계산
            total_capacity = 0
            for channel in range(channels):
                channel_data = img_array[:, :, channel].astype(np.int32)
                iwt_coefficients = self._iwt_2d_forward(channel_data)
                
                # 임베딩 가능한 계수 개수
                embeddable_count = 0
                for pos in high_freq_positions:
                    if abs(iwt_coefficients[pos]) > 1:
                        embeddable_count += 1
                
                total_capacity += embeddable_count
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, total_capacity - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_wavelet_domain(self, image_path: str) -> dict:
        """이미지의 웨이블릿 도메인 분석"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            analysis_results = {}
            
            for channel in range(channels):
                channel_data = img_array[:, :, channel].astype(np.int32)
                iwt_coefficients = self._iwt_2d_forward(channel_data)
                
                # 서브밴드별 분석
                half_h, half_w = height // 2, width // 2
                
                # LL (저주파)
                ll_band = iwt_coefficients[:half_h, :half_w]
                # LH (수직 고주파)
                lh_band = iwt_coefficients[half_h:, :half_w]
                # HL (수평 고주파)
                hl_band = iwt_coefficients[:half_h, half_w:]
                # HH (대각선 고주파)
                hh_band = iwt_coefficients[half_h:, half_w:]
                
                channel_analysis = {
                    'LL_energy': float(np.sum(ll_band ** 2)),
                    'LH_energy': float(np.sum(lh_band ** 2)),
                    'HL_energy': float(np.sum(hl_band ** 2)),
                    'HH_energy': float(np.sum(hh_band ** 2)),
                    'high_freq_coefficients': int(np.sum(np.abs(iwt_coefficients[half_h:, half_w:]) > 1)),
                    'embeddable_positions': len(self._select_embedding_positions(iwt_coefficients, 10000))
                }
                
                analysis_results[f'channel_{channel}'] = channel_analysis
            
            # 전체 분석
            total_embeddable = sum(ch['embeddable_positions'] for ch in analysis_results.values())
            total_high_freq = sum(ch['high_freq_coefficients'] for ch in analysis_results.values())
            
            analysis_results['summary'] = {
                'total_embeddable_positions': total_embeddable,
                'total_high_freq_coefficients': total_high_freq,
                'capacity_bytes': self.get_capacity(image_path),
                'embedding_efficiency': total_embeddable / (height * width * channels) if height * width * channels > 0 else 0,
                'suitability': 'Excellent' if total_embeddable > height * width * 0.3 else
                             'Good' if total_embeddable > height * width * 0.2 else
                             'Fair' if total_embeddable > height * width * 0.1 else 'Poor'
            }
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"웨이블릿 도메인 분석 실패: {e}")
            return {}
    
    def visualize_wavelet_subbands(self, image_path: str, output_path: str) -> bool:
        """웨이블릿 서브밴드 시각화"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # 그레이스케일로 변환하여 시각화
            gray_image = image.convert('L')
            img_array = np.array(gray_image).astype(np.int32)
            
            # IWT 변환
            iwt_coefficients = self._iwt_2d_forward(img_array)
            height, width = iwt_coefficients.shape
            half_h, half_w = height // 2, width // 2
            
            # 서브밴드 분리
            ll = iwt_coefficients[:half_h, :half_w]
            lh = iwt_coefficients[half_h:, :half_w]
            hl = iwt_coefficients[:half_h, half_w:]
            hh = iwt_coefficients[half_h:, half_w:]
            
            # 정규화
            def normalize_subband(band):
                band_min, band_max = band.min(), band.max()
                if band_max > band_min:
                    return ((band - band_min) / (band_max - band_min) * 255).astype(np.uint8)
                return np.zeros_like(band, dtype=np.uint8)
            
            ll_norm = normalize_subband(ll)
            lh_norm = normalize_subband(np.abs(lh))
            hl_norm = normalize_subband(np.abs(hl))
            hh_norm = normalize_subband(np.abs(hh))
            
            # 서브밴드 결합
            top_row = np.hstack([ll_norm, hl_norm])
            bottom_row = np.hstack([lh_norm, hh_norm])
            combined = np.vstack([top_row, bottom_row])
            
            # 결과 저장
            result_image = Image.fromarray(combined)
            result_image.save(output_path)
            
            logger.info(f"웨이블릿 서브밴드 시각화 저장: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"웨이블릿 서브밴드 시각화 실패: {e}")
            return False