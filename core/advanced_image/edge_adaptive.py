"""
Edge Adaptive 스테가노그래피 알고리즘

에지 적응형 스테가노그래피는 이미지의 엣지(가장자리) 영역을 감지하고,
이러한 복잡한 텍스처 영역에 우선적으로 데이터를 은닉하는 기법입니다.
엣지 영역은 인간의 시각적 인지에 덜 민감하므로 더 많은 데이터를 숨길 수 있습니다.

Reference: Luo et al. (2010), "Edge Adaptive Image Steganography Based on LSB Matching Revisited"
"""

import numpy as np
from PIL import Image, ImageFilter
import cv2
from typing import Optional, List, Tuple
import logging
from ..utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class EdgeAdaptiveSteganography:
    """Edge Adaptive 스테가노그래피 구현"""
    
    def __init__(self, edge_threshold: int = 30):
        """
        Args:
            edge_threshold: 엣지 감지 임계값 (기본값: 30)
        """
        self.edge_threshold = edge_threshold
    
    def _detect_edges(self, image_array: np.ndarray) -> np.ndarray:
        """Canny 엣지 감지를 사용하여 엣지 맵 생성"""
        # 그레이스케일 변환
        if len(image_array.shape) == 3:
            gray = cv2.cvtColor(image_array, cv2.COLOR_RGB2GRAY)
        else:
            gray = image_array
        
        # Canny 엣지 감지
        edges = cv2.Canny(gray, self.edge_threshold, self.edge_threshold * 3)
        
        return edges
    
    def _calculate_edge_strength(self, image_array: np.ndarray, x: int, y: int, 
                                window_size: int = 3) -> float:
        """특정 위치에서의 엣지 강도 계산"""
        height, width = image_array.shape[:2]
        
        # 윈도우 경계 확인
        half_window = window_size // 2
        x_start = max(0, x - half_window)
        x_end = min(width, x + half_window + 1)
        y_start = max(0, y - half_window)  
        y_end = min(height, y + half_window + 1)
        
        # 윈도우 영역 추출
        if len(image_array.shape) == 3:
            window = image_array[y_start:y_end, x_start:x_end, :]
            # RGB를 그레이스케일로 변환
            gray_window = np.mean(window, axis=2)
        else:
            gray_window = image_array[y_start:y_end, x_start:x_end]
        
        if gray_window.size == 0:
            return 0.0
        
        # Sobel 연산자를 사용한 그래디언트 계산
        if gray_window.shape[0] >= 3 and gray_window.shape[1] >= 3:
            sobelx = cv2.Sobel(gray_window.astype(np.float32), cv2.CV_64F, 1, 0, ksize=3)
            sobely = cv2.Sobel(gray_window.astype(np.float32), cv2.CV_64F, 0, 1, ksize=3)
            
            # 그래디언트 크기 계산
            gradient_magnitude = np.sqrt(sobelx**2 + sobely**2)
            return np.mean(gradient_magnitude)
        
        return 0.0
    
    def _generate_embedding_map(self, image_array: np.ndarray) -> np.ndarray:
        """임베딩 우선순위 맵 생성 (엣지 강도 기반)"""
        height, width = image_array.shape[:2]
        embedding_map = np.zeros((height, width), dtype=np.float32)
        
        for y in range(height):
            for x in range(width):
                edge_strength = self._calculate_edge_strength(image_array, x, y)
                embedding_map[y, x] = edge_strength
        
        return embedding_map
    
    def _get_embedding_positions(self, embedding_map: np.ndarray, 
                                capacity_needed: int) -> List[Tuple[int, int]]:
        """엣지 강도 순으로 임베딩 위치 반환"""
        height, width = embedding_map.shape
        
        # 모든 위치와 엣지 강도를 리스트로 생성
        positions_with_strength = []
        for y in range(height):
            for x in range(width):
                strength = embedding_map[y, x]
                positions_with_strength.append((strength, y, x))
        
        # 엣지 강도 내림차순으로 정렬
        positions_with_strength.sort(reverse=True)
        
        # 필요한 용량만큼 위치 반환
        embedding_positions = []
        for i, (strength, y, x) in enumerate(positions_with_strength):
            if i >= capacity_needed:
                break
            if strength > 0:  # 최소 엣지 강도 조건
                embedding_positions.append((y, x))
        
        return embedding_positions
    
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None) -> bool:
        """Edge Adaptive 방법으로 메시지 임베딩"""
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
            
            # 엣지 맵 생성
            embedding_map = self._generate_embedding_map(img_array)
            
            # 필요한 용량만큼 임베딩 위치 선택
            embedding_positions = self._get_embedding_positions(
                embedding_map, len(total_bits) * channels
            )
            
            if len(embedding_positions) * channels < len(total_bits):
                logger.error(f"임베딩 용량 부족. 필요: {len(total_bits)}, 가용: {len(embedding_positions) * channels}")
                return False
            
            # LSB 임베딩 (엣지 영역 우선)
            new_img_array = img_array.copy()
            bit_index = 0
            
            for y, x in embedding_positions:
                if bit_index >= len(total_bits):
                    break
                
                for channel in range(channels):
                    if bit_index >= len(total_bits):
                        break
                    
                    # 현재 픽셀 값
                    pixel_value = new_img_array[y, x, channel]
                    
                    # LSB 교체
                    bit = int(total_bits[bit_index])
                    new_pixel_value = (pixel_value & 0xFE) | bit
                    new_img_array[y, x, channel] = new_pixel_value
                    
                    bit_index += 1
            
            # 결과 이미지 저장
            result_image = Image.fromarray(new_img_array.astype(np.uint8))
            result_image.save(output_path)
            
            logger.info(f"Edge Adaptive 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Edge Adaptive 임베딩 실패: {e}")
            return False
    
    def extract_message(self, input_path: str, password: Optional[str] = None) -> Optional[str]:
        """Edge Adaptive 방법으로 메시지 추출"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 엣지 맵 생성 (임베딩과 동일한 방식)
            embedding_map = self._generate_embedding_map(img_array)
            
            # 임베딩 위치 복원
            embedding_positions = self._get_embedding_positions(
                embedding_map, 32 * channels  # 길이 정보만 먼저 추출
            )
            
            # 메시지 길이 추출 (처음 32비트)
            extracted_bits = ""
            bit_count = 0
            
            for y, x in embedding_positions:
                if bit_count >= 32:
                    break
                
                for channel in range(channels):
                    if bit_count >= 32:
                        break
                    
                    pixel_value = img_array[y, x, channel]
                    bit = pixel_value & 1
                    extracted_bits += str(bit)
                    bit_count += 1
            
            if len(extracted_bits) < 32:
                logger.error("메시지 길이 정보를 읽을 수 없습니다")
                return None
            
            message_length = int(extracted_bits[:32], 2)
            logger.info(f"메시지 길이: {message_length} 비트")
            
            if message_length <= 0 or message_length > 1000000:  # 1MB 제한
                logger.error("유효하지 않은 메시지 길이")
                return None
            
            # 전체 메시지를 위한 임베딩 위치 재계산
            total_bits_needed = 32 + message_length
            embedding_positions = self._get_embedding_positions(
                embedding_map, total_bits_needed * channels
            )
            
            # 실제 메시지 추출
            extracted_bits = ""
            bit_count = 0
            
            for y, x in embedding_positions:
                for channel in range(channels):
                    if bit_count >= total_bits_needed:
                        break
                    
                    pixel_value = img_array[y, x, channel]
                    bit = pixel_value & 1
                    extracted_bits += str(bit)
                    bit_count += 1
                
                if bit_count >= total_bits_needed:
                    break
            
            # 길이 정보 제거하고 메시지 부분만 추출
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
            logger.error(f"Edge Adaptive 추출 실패: {e}")
            return None
    
    def get_capacity(self, image_path: str) -> int:
        """이미지의 Edge Adaptive 임베딩 용량 반환 (바이트 단위)"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 엣지 맵 생성
            embedding_map = self._generate_embedding_map(img_array)
            
            # 엣지 강도가 0보다 큰 픽셀 수 계산
            valid_positions = np.sum(embedding_map > 0)
            
            # 각 픽셀의 각 채널에 1비트씩 임베딩 가능
            total_bits = valid_positions * channels
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, total_bits - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_edge_distribution(self, image_path: str) -> dict:
        """이미지의 엣지 분포 분석"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 엣지 맵 생성
            embedding_map = self._generate_embedding_map(img_array)
            edges = self._detect_edges(img_array)
            
            # 통계 계산
            total_pixels = height * width
            edge_pixels = np.sum(edges > 0)
            strong_edge_pixels = np.sum(embedding_map > self.edge_threshold)
            
            edge_ratio = edge_pixels / total_pixels
            strong_edge_ratio = strong_edge_pixels / total_pixels
            
            # 엣지 강도 히스토그램
            edge_strengths = embedding_map[embedding_map > 0]
            
            return {
                'total_pixels': total_pixels,
                'edge_pixels': int(edge_pixels),
                'strong_edge_pixels': int(strong_edge_pixels),
                'edge_ratio': edge_ratio,
                'strong_edge_ratio': strong_edge_ratio,
                'capacity_bytes': self.get_capacity(image_path),
                'avg_edge_strength': float(np.mean(edge_strengths)) if len(edge_strengths) > 0 else 0.0,
                'max_edge_strength': float(np.max(edge_strengths)) if len(edge_strengths) > 0 else 0.0,
                'suitability': 'Excellent' if edge_ratio > 0.3 else
                             'Good' if edge_ratio > 0.2 else
                             'Fair' if edge_ratio > 0.1 else 'Poor'
            }
            
        except Exception as e:
            logger.error(f"엣지 분포 분석 실패: {e}")
            return {}
    
    def visualize_embedding_map(self, image_path: str, output_path: str) -> bool:
        """임베딩 맵 시각화"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # 엣지 맵 생성
            embedding_map = self._generate_embedding_map(img_array)
            
            # 정규화하여 0-255 범위로 변환
            normalized_map = ((embedding_map - embedding_map.min()) / 
                            (embedding_map.max() - embedding_map.min() + 1e-8) * 255).astype(np.uint8)
            
            # 히트맵으로 저장
            heatmap = cv2.applyColorMap(normalized_map, cv2.COLORMAP_JET)
            heatmap_rgb = cv2.cvtColor(heatmap, cv2.COLOR_BGR2RGB)
            
            result_image = Image.fromarray(heatmap_rgb)
            result_image.save(output_path)
            
            logger.info(f"엣지 맵 시각화 저장: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"엣지 맵 시각화 실패: {e}")
            return False