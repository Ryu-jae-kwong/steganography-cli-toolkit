"""
Spread Spectrum 스테가노그래피 알고리즘

Spread Spectrum 스테가노그래피는 통신에서 사용되는 확산 스펙트럼 기법을
이미지 은닉에 응용한 방법입니다. 의사 난수 시퀀스를 사용하여 데이터를
이미지 전체에 분산시켜 은닉하므로 탐지가 어렵고 노이즈에 강합니다.

Reference: Cox et al. (1997), "Secure spread spectrum watermarking for multimedia"
"""

import numpy as np
from PIL import Image
from typing import Optional, List, Tuple
import hashlib
import logging
from ..utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class SpreadSpectrumSteganography:
    """Spread Spectrum 스테가노그래피 구현"""
    
    def __init__(self, spreading_factor: int = 8, seed: Optional[int] = None):
        """
        Args:
            spreading_factor: 확산 인수 (각 비트를 몇 개의 픽셀에 분산할지)
            seed: 의사 난수 생성기 시드 (재현성을 위해)
        """
        self.spreading_factor = spreading_factor
        self.seed = seed or 12345
        self.pn_sequence = None  # PN(Pseudo-Noise) 시퀀스
    
    def _generate_pn_sequence(self, length: int, seed: int = None) -> np.ndarray:
        """의사 난수 시퀀스 생성 (Gold sequence 기반)"""
        if seed is None:
            seed = self.seed
        
        np.random.seed(seed)
        
        # 이진 의사 난수 시퀀스 생성 (-1 또는 1)
        pn_sequence = np.random.choice([-1, 1], size=length)
        
        return pn_sequence
    
    def _modulate_data(self, data_bits: str) -> np.ndarray:
        """데이터 비트를 확산 스펙트럼으로 변조"""
        # 각 비트를 spreading_factor 개의 칩으로 확산
        modulated = []
        
        for bit_char in data_bits:
            bit = int(bit_char)
            # 0은 -1로, 1은 1로 매핑
            symbol = 1 if bit == 1 else -1
            
            # PN 시퀀스와 곱하여 확산
            pn_chunk = self._generate_pn_sequence(self.spreading_factor, 
                                                self.seed + len(modulated))
            spread_symbol = symbol * pn_chunk
            modulated.extend(spread_symbol)
        
        return np.array(modulated)
    
    def _demodulate_data(self, received_signal: np.ndarray, num_bits: int) -> str:
        """수신된 신호에서 데이터 비트 복조"""
        demodulated_bits = []
        
        for i in range(num_bits):
            start_idx = i * self.spreading_factor
            end_idx = start_idx + self.spreading_factor
            
            if end_idx > len(received_signal):
                break
            
            # 해당 비트에 대한 신호 추출
            received_chunk = received_signal[start_idx:end_idx]
            
            # 같은 PN 시퀀스로 역확산
            pn_chunk = self._generate_pn_sequence(self.spreading_factor, 
                                                self.seed + i)
            
            # 상관(correlation) 계산
            correlation = np.sum(received_chunk * pn_chunk)
            
            # 양수면 1, 음수면 0으로 판정
            bit = '1' if correlation > 0 else '0'
            demodulated_bits.append(bit)
        
        return ''.join(demodulated_bits)
    
    def _create_embedding_map(self, height: int, width: int, channels: int,
                            total_chips: int, seed: int = None) -> List[Tuple[int, int, int]]:
        """임베딩 위치 맵 생성 (의사 랜덤 위치)"""
        if seed is None:
            seed = self.seed
        
        np.random.seed(seed)
        
        # 모든 가능한 위치
        all_positions = []
        for c in range(channels):
            for h in range(height):
                for w in range(width):
                    all_positions.append((h, w, c))
        
        # 필요한 만큼 랜덤하게 선택
        if total_chips > len(all_positions):
            # 부족한 경우 반복 사용
            selected_positions = []
            for i in range(total_chips):
                selected_positions.append(all_positions[i % len(all_positions)])
        else:
            selected_positions = np.random.choice(len(all_positions), 
                                                size=total_chips, replace=False)
            selected_positions = [all_positions[idx] for idx in selected_positions]
        
        return selected_positions
    
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None, embedding_strength: float = 10.0) -> bool:
        """Spread Spectrum 방법으로 메시지 임베딩"""
        try:
            # 이미지 로드
            image = Image.open(input_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image).astype(np.float32)
            height, width, channels = img_array.shape
            
            # 메시지 암호화 (필요시)
            if password:
                # 패스워드를 시드로 활용
                seed_hash = int(hashlib.md5(password.encode()).hexdigest()[:8], 16)
                self.seed = seed_hash
                
                encrypted_data = encrypt_message(message.encode('utf-8'), password)
                message_bits = ''.join(format(byte, '08b') for byte in encrypted_data)
            else:
                message_bytes = message.encode('utf-8')
                message_bits = ''.join(format(byte, '08b') for byte in message_bytes)
            
            # 메시지 길이 정보 추가 (32비트)
            length_bits = format(len(message_bits), '032b')
            total_bits = length_bits + message_bits
            
            logger.info(f"임베딩할 총 비트 수: {len(total_bits)}")
            
            # 필요한 총 칩 수 계산
            total_chips = len(total_bits) * self.spreading_factor
            total_pixels = height * width * channels
            
            if total_chips > total_pixels:
                logger.error(f"이미지 크기가 부족합니다. 필요: {total_chips}, 가용: {total_pixels}")
                return False
            
            # 데이터 변조 (확산)
            modulated_signal = self._modulate_data(total_bits)
            
            # 임베딩 위치 결정
            embedding_positions = self._create_embedding_map(
                height, width, channels, total_chips, self.seed
            )
            
            # 스테고 이미지 생성
            stego_img = img_array.copy()
            
            for i, (h, w, c) in enumerate(embedding_positions):
                if i >= len(modulated_signal):
                    break
                
                # 원본 픽셀값에 확산된 신호 추가
                original_pixel = img_array[h, w, c]
                modification = modulated_signal[i] * embedding_strength
                
                new_pixel = original_pixel + modification
                
                # 픽셀 값 클리핑
                stego_img[h, w, c] = np.clip(new_pixel, 0, 255)
            
            # 결과 이미지 저장
            result_image = Image.fromarray(stego_img.astype(np.uint8))
            result_image.save(output_path)
            
            logger.info(f"Spread Spectrum 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Spread Spectrum 임베딩 실패: {e}")
            return False
    
    def extract_message(self, stego_path: str, original_path: str = None,
                       password: Optional[str] = None, 
                       embedding_strength: float = 10.0) -> Optional[str]:
        """Spread Spectrum 방법으로 메시지 추출"""
        try:
            # 스테고 이미지 로드
            stego_image = Image.open(stego_path)
            if stego_image.mode != 'RGB':
                stego_image = stego_image.convert('RGB')
            
            stego_array = np.array(stego_image).astype(np.float32)
            height, width, channels = stego_array.shape
            
            # 원본 이미지가 있는 경우 차이 계산
            if original_path:
                original_image = Image.open(original_path)
                if original_image.mode != 'RGB':
                    original_image = original_image.convert('RGB')
                
                original_array = np.array(original_image).astype(np.float32)
                difference = stego_array - original_array
            else:
                # 원본이 없는 경우 스테고 이미지만 사용 (블라인드 추출)
                difference = stego_array
                logger.info("블라인드 추출 모드: 원본 이미지 없이 추출 시도")
            
            # 패스워드가 있는 경우 시드 복원
            if password:
                seed_hash = int(hashlib.md5(password.encode()).hexdigest()[:8], 16)
                self.seed = seed_hash
            
            # 길이 정보 추출을 위한 임베딩 위치 (처음 32비트)
            length_chips = 32 * self.spreading_factor
            length_positions = self._create_embedding_map(
                height, width, channels, length_chips, self.seed
            )
            
            # 길이 정보에 해당하는 신호 추출
            length_signal = []
            for h, w, c in length_positions:
                if original_path:
                    received_chip = difference[h, w, c] / embedding_strength
                else:
                    # 블라인드 추출에서는 통계적 방법 사용
                    received_chip = (stego_array[h, w, c] - 128) / embedding_strength
                
                length_signal.append(received_chip)
            
            # 길이 정보 복조
            length_bits = self._demodulate_data(np.array(length_signal), 32)
            
            try:
                message_length = int(length_bits, 2)
                logger.info(f"추출된 메시지 길이: {message_length} 비트")
                
                if message_length <= 0 or message_length > 1000000:
                    logger.error("유효하지 않은 메시지 길이")
                    return None
            except ValueError:
                logger.error("길이 정보 파싱 실패")
                return None
            
            # 전체 메시지 추출
            total_bits = 32 + message_length
            total_chips = total_bits * self.spreading_factor
            
            all_positions = self._create_embedding_map(
                height, width, channels, total_chips, self.seed
            )
            
            # 전체 신호 추출
            received_signal = []
            for h, w, c in all_positions:
                if original_path:
                    received_chip = difference[h, w, c] / embedding_strength
                else:
                    received_chip = (stego_array[h, w, c] - 128) / embedding_strength
                
                received_signal.append(received_chip)
            
            # 전체 데이터 복조
            all_bits = self._demodulate_data(np.array(received_signal), total_bits)
            
            # 메시지 부분만 추출 (길이 정보 제외)
            message_bits = all_bits[32:32 + message_length]
            
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
            logger.error(f"Spread Spectrum 추출 실패: {e}")
            return None
    
    def get_capacity(self, image_path: str) -> int:
        """이미지의 Spread Spectrum 임베딩 용량 반환 (바이트 단위)"""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # 총 픽셀 수
            total_pixels = height * width * channels
            
            # 확산 인수를 고려한 최대 비트 수
            max_bits = total_pixels // self.spreading_factor
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, max_bits - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_embedding_quality(self, original_path: str, stego_path: str) -> dict:
        """임베딩 품질 분석 (PSNR, MSE 등)"""
        try:
            # 이미지 로드
            original = Image.open(original_path)
            stego = Image.open(stego_path)
            
            if original.mode != 'RGB':
                original = original.convert('RGB')
            if stego.mode != 'RGB':
                stego = stego.convert('RGB')
            
            original_array = np.array(original).astype(np.float32)
            stego_array = np.array(stego).astype(np.float32)
            
            # MSE 계산
            mse = np.mean((original_array - stego_array) ** 2)
            
            # PSNR 계산
            if mse == 0:
                psnr = float('inf')
            else:
                psnr = 20 * np.log10(255.0 / np.sqrt(mse))
            
            # SSIM 간단 버전 (구조적 유사성)
            def simple_ssim(img1, img2):
                mu1 = np.mean(img1)
                mu2 = np.mean(img2)
                sigma1_sq = np.var(img1)
                sigma2_sq = np.var(img2)
                sigma12 = np.mean((img1 - mu1) * (img2 - mu2))
                
                c1 = (0.01 * 255) ** 2
                c2 = (0.03 * 255) ** 2
                
                numerator = (2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)
                denominator = (mu1 ** 2 + mu2 ** 2 + c1) * (sigma1_sq + sigma2_sq + c2)
                
                return numerator / denominator
            
            # 채널별 SSIM 계산
            ssim_values = []
            for c in range(original_array.shape[2]):
                ssim_c = simple_ssim(original_array[:, :, c], stego_array[:, :, c])
                ssim_values.append(ssim_c)
            
            avg_ssim = np.mean(ssim_values)
            
            # 히스토그램 분석
            def histogram_similarity(img1, img2):
                hist1 = np.histogram(img1.flatten(), bins=256, range=[0, 256])[0]
                hist2 = np.histogram(img2.flatten(), bins=256, range=[0, 256])[0]
                
                # 정규화
                hist1 = hist1 / np.sum(hist1)
                hist2 = hist2 / np.sum(hist2)
                
                # 히스토그램 교집합
                return np.sum(np.minimum(hist1, hist2))
            
            hist_similarity = histogram_similarity(original_array, stego_array)
            
            return {
                'MSE': float(mse),
                'PSNR': float(psnr),
                'SSIM': float(avg_ssim),
                'histogram_similarity': float(hist_similarity),
                'capacity_bytes': self.get_capacity(original_path),
                'spreading_factor': self.spreading_factor,
                'quality_score': 'Excellent' if psnr > 40 else
                               'Good' if psnr > 30 else
                               'Fair' if psnr > 20 else 'Poor',
                'imperceptibility': 'High' if psnr > 35 and avg_ssim > 0.95 else
                                  'Medium' if psnr > 25 and avg_ssim > 0.9 else 'Low'
            }
            
        except Exception as e:
            logger.error(f"품질 분석 실패: {e}")
            return {}
    
    def test_robustness(self, stego_path: str, original_path: str = None,
                       password: Optional[str] = None) -> dict:
        """다양한 공격에 대한 강인성 테스트"""
        try:
            # 기본 추출 테스트
            original_message = self.extract_message(stego_path, original_path, password)
            
            if not original_message:
                return {'error': '기본 추출 실패'}
            
            stego_image = Image.open(stego_path)
            results = {'original_extraction': 'Success'}
            
            # JPEG 압축 공격
            try:
                import io
                jpeg_buffer = io.BytesIO()
                stego_image.save(jpeg_buffer, format='JPEG', quality=90)
                jpeg_buffer.seek(0)
                
                jpeg_attacked = Image.open(jpeg_buffer)
                temp_path = stego_path.replace('.png', '_jpeg_attacked.jpg')
                jpeg_attacked.save(temp_path)
                
                jpeg_message = self.extract_message(temp_path, original_path, password)
                results['jpeg_90_attack'] = 'Success' if jpeg_message == original_message else 'Failed'
                
                # 임시 파일 삭제
                import os
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
            except Exception:
                results['jpeg_90_attack'] = 'Error'
            
            # 가우시안 노이즈 공격
            try:
                stego_array = np.array(stego_image).astype(np.float32)
                noise = np.random.normal(0, 5, stego_array.shape)
                noisy_array = np.clip(stego_array + noise, 0, 255).astype(np.uint8)
                
                noisy_image = Image.fromarray(noisy_array)
                temp_path = stego_path.replace('.png', '_noise_attacked.png')
                noisy_image.save(temp_path)
                
                noise_message = self.extract_message(temp_path, original_path, password)
                results['gaussian_noise_attack'] = 'Success' if noise_message == original_message else 'Failed'
                
                # 임시 파일 삭제
                import os
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
            except Exception:
                results['gaussian_noise_attack'] = 'Error'
            
            # 크기 조정 공격
            try:
                # 50% 축소 후 다시 확대
                small_image = stego_image.resize((stego_image.width // 2, stego_image.height // 2))
                resized_image = small_image.resize((stego_image.width, stego_image.height))
                
                temp_path = stego_path.replace('.png', '_resize_attacked.png')
                resized_image.save(temp_path)
                
                resize_message = self.extract_message(temp_path, original_path, password)
                results['resize_attack'] = 'Success' if resize_message == original_message else 'Failed'
                
                # 임시 파일 삭제
                import os
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
            except Exception:
                results['resize_attack'] = 'Error'
            
            # 강인성 점수 계산
            success_count = sum(1 for v in results.values() if v == 'Success')
            total_tests = len(results)
            robustness_score = success_count / total_tests
            
            results['robustness_score'] = robustness_score
            results['robustness_level'] = 'High' if robustness_score > 0.8 else \
                                        'Medium' if robustness_score > 0.6 else 'Low'
            
            return results
            
        except Exception as e:
            logger.error(f"강인성 테스트 실패: {e}")
            return {'error': str(e)}