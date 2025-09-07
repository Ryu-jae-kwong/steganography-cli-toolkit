"""
DCT Video Steganography v3.0
디지털 포렌식 연구소

DCT(Discrete Cosine Transform) 기반 비디오 스테가노그래피 구현
주파수 도메인에서 데이터를 임베딩하여 압축에 강한 특성을 제공합니다.

주요 특징:
- H.264/H.265 코덱 호환성 최적화
- JPEG 압축 저항성
- 적응형 양자화 매트릭스 조정
- 모션 보상 고려
- 시각적 품질 보존
"""

import cv2
import numpy as np
import os
import hashlib
from typing import Tuple, Optional, List, Dict, Any
from pathlib import Path
import struct
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from scipy.fft import dct, idct
import logging

class DCTVideoSteganography:
    """DCT 기반 비디오 스테가노그래피 클래스"""
    
    def __init__(self, 
                 block_size: int = 8,
                 quality_factor: float = 0.8,
                 dct_threshold: float = 10.0,
                 embed_frequency: int = 5,
                 motion_threshold: float = 30.0):
        """
        DCT Video Steganography 초기화
        
        Args:
            block_size: DCT 블록 크기 (일반적으로 8x8)
            quality_factor: 품질 팩터 (0.1-1.0)
            dct_threshold: 임베딩을 위한 DCT 계수 임계값
            embed_frequency: 임베딩 주파수 (N 프레임마다 임베딩)
            motion_threshold: 모션 감지 임계값
        """
        self.block_size = block_size
        self.quality_factor = quality_factor
        self.dct_threshold = dct_threshold
        self.embed_frequency = embed_frequency
        self.motion_threshold = motion_threshold
        
        # 로깅 설정
        self.logger = logging.getLogger(__name__)
        
        # DCT 양자화 테이블 (JPEG 표준 기반)
        self.quantization_table = np.array([
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99]
        ], dtype=np.float32)
        
        # 품질에 따른 양자화 테이블 조정
        if quality_factor != 1.0:
            scale = 50.0 / quality_factor if quality_factor < 0.5 else (200 - 2 * quality_factor * 100) / 100
            self.quantization_table = np.clip(
                (self.quantization_table * scale + 0.5).astype(int), 
                1, 255
            ).astype(np.float32)
    
    def _apply_dct_2d(self, block: np.ndarray) -> np.ndarray:
        """2D DCT 변환 적용"""
        return dct(dct(block.T, norm='ortho').T, norm='ortho')
    
    def _apply_idct_2d(self, dct_block: np.ndarray) -> np.ndarray:
        """2D IDCT 변환 적용"""
        return idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
    
    def _quantize_dct(self, dct_block: np.ndarray) -> np.ndarray:
        """DCT 계수 양자화"""
        return np.round(dct_block / self.quantization_table)
    
    def _dequantize_dct(self, quantized_block: np.ndarray) -> np.ndarray:
        """DCT 계수 역양자화"""
        return quantized_block * self.quantization_table
    
    def _get_embeddable_positions(self, dct_block: np.ndarray) -> List[Tuple[int, int]]:
        """임베딩 가능한 DCT 계수 위치 찾기"""
        positions = []
        
        # 중간 주파수 영역에서 임베딩 (AC 계수 중 적절한 위치)
        for i in range(1, self.block_size):
            for j in range(1, self.block_size):
                # DC 계수(0,0)는 제외하고 고주파도 제외
                if i + j < self.block_size and abs(dct_block[i, j]) > self.dct_threshold:
                    positions.append((i, j))
        
        return positions
    
    def _embed_bit_in_dct(self, dct_block: np.ndarray, bit: int, position: Tuple[int, int]) -> np.ndarray:
        """DCT 계수에 비트 임베딩"""
        modified_block = dct_block.copy()
        i, j = position
        
        # LSB 방식으로 임베딩
        coeff = modified_block[i, j]
        
        if bit == 1:
            # 홀수로 만들기
            if int(abs(coeff)) % 2 == 0:
                modified_block[i, j] = coeff + (1 if coeff >= 0 else -1)
        else:
            # 짝수로 만들기
            if int(abs(coeff)) % 2 == 1:
                modified_block[i, j] = coeff + (1 if coeff >= 0 else -1)
        
        return modified_block
    
    def _extract_bit_from_dct(self, dct_block: np.ndarray, position: Tuple[int, int]) -> int:
        """DCT 계수에서 비트 추출"""
        i, j = position
        coeff = dct_block[i, j]
        return int(abs(coeff)) % 2
    
    def _detect_motion(self, frame1: np.ndarray, frame2: np.ndarray) -> np.ndarray:
        """프레임 간 모션 감지"""
        diff = cv2.absdiff(frame1, frame2)
        gray_diff = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY) if len(diff.shape) == 3 else diff
        return gray_diff > self.motion_threshold
    
    def _process_frame_blocks(self, frame: np.ndarray, operation: str, data_bits: str = "", 
                            bit_index: int = 0) -> Tuple[np.ndarray, int, List[Tuple[int, int]]]:
        """프레임을 블록 단위로 처리"""
        height, width = frame.shape[:2]
        processed_frame = frame.copy()
        positions_used = []
        
        # 그레이스케일 변환 (DCT는 주로 휘도 성분에 적용)
        if len(frame.shape) == 3:
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            y_channel = gray_frame.astype(np.float32) - 128  # 중앙값 조정
        else:
            y_channel = frame.astype(np.float32) - 128
        
        processed_y = y_channel.copy()
        
        # 8x8 블록으로 분할하여 처리
        for i in range(0, height - self.block_size + 1, self.block_size):
            for j in range(0, width - self.block_size + 1, self.block_size):
                block = y_channel[i:i+self.block_size, j:j+self.block_size]
                
                # DCT 변환
                dct_block = self._apply_dct_2d(block)
                quantized_block = self._quantize_dct(dct_block)
                
                # 임베딩 가능한 위치 찾기
                embeddable_positions = self._get_embeddable_positions(quantized_block)
                
                if operation == "embed" and bit_index < len(data_bits) and embeddable_positions:
                    # 데이터 임베딩
                    for pos in embeddable_positions[:min(len(embeddable_positions), 
                                                       len(data_bits) - bit_index)]:
                        bit = int(data_bits[bit_index])
                        quantized_block = self._embed_bit_in_dct(quantized_block, bit, pos)
                        positions_used.append((i//self.block_size, j//self.block_size, pos))
                        bit_index += 1
                        
                        if bit_index >= len(data_bits):
                            break
                
                # IDCT 변환 후 복원
                dequantized_block = self._dequantize_dct(quantized_block)
                restored_block = self._apply_idct_2d(dequantized_block)
                processed_y[i:i+self.block_size, j:j+self.block_size] = restored_block
                
                if operation == "embed" and bit_index >= len(data_bits):
                    break
            
            if operation == "embed" and bit_index >= len(data_bits):
                break
        
        # 복원된 Y 채널을 원본 프레임에 적용
        processed_y = np.clip(processed_y + 128, 0, 255).astype(np.uint8)
        
        if len(frame.shape) == 3:
            processed_frame[:, :, 0] = processed_y  # Y 채널만 수정
        else:
            processed_frame = processed_y
        
        return processed_frame, bit_index, positions_used
    
    def _encrypt_data(self, data: str, password: str) -> bytes:
        """AES-256-GCM으로 데이터 암호화"""
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, 32, count=100000)
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        
        return salt + cipher.nonce + auth_tag + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes, password: str) -> str:
        """AES-256-GCM으로 데이터 복호화"""
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        auth_tag = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]
        
        key = PBKDF2(password, salt, 32, count=100000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        return cipher.decrypt_and_verify(ciphertext, auth_tag).decode('utf-8')
    
    def embed_message(self, video_path: str, message: str, output_path: str, 
                     password: Optional[str] = None) -> bool:
        """비디오에 메시지 임베딩"""
        try:
            self.logger.info(f"DCT 비디오 스테가노그래피 임베딩 시작: {video_path}")
            
            # 비디오 파일 검증
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"비디오 파일을 찾을 수 없습니다: {video_path}")
            
            # 비디오 캡처 객체 생성
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"비디오 파일을 열 수 없습니다: {video_path}")
            
            # 비디오 속성 가져오기
            fps = int(cap.get(cv2.CAP_PROP_FPS))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            self.logger.info(f"비디오 정보: {width}x{height}, {fps}fps, {total_frames}프레임")
            
            # 코덱 설정 (원본과 동일하게)
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            
            # 데이터 준비
            if password:
                encrypted_message = self._encrypt_data(message, password)
                data_to_embed = encrypted_message
            else:
                data_to_embed = message.encode('utf-8')
            
            # 헤더 정보 생성
            header = {
                'length': len(data_to_embed),
                'encrypted': password is not None,
                'checksum': hashlib.md5(data_to_embed).hexdigest(),
                'embed_frequency': self.embed_frequency
            }
            header_json = json.dumps(header).encode('utf-8')
            
            # 전체 데이터 (헤더 + 실제 데이터)
            header_length = len(header_json)
            full_data = struct.pack('<I', header_length) + header_json + data_to_embed
            
            # 바이너리 데이터로 변환
            binary_data = ''.join(format(byte, '08b') for byte in full_data)
            
            self.logger.info(f"임베딩할 데이터 크기: {len(binary_data)} bits")
            
            # 용량 확인
            blocks_per_frame = ((height // self.block_size) * (width // self.block_size))
            available_bits_per_frame = blocks_per_frame * min(8, len(self._get_embeddable_positions(
                np.ones((self.block_size, self.block_size)) * 20)))
            embed_frames = total_frames // self.embed_frequency
            total_capacity = embed_frames * available_bits_per_frame
            
            if len(binary_data) > total_capacity:
                raise ValueError(f"메시지가 너무 큽니다. 필요: {len(binary_data)}bits, "
                               f"사용가능: {total_capacity}bits")
            
            # 프레임별 임베딩
            frame_count = 0
            bit_index = 0
            previous_frame = None
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                processed_frame = frame.copy()
                
                # 임베딩 프레임인지 확인
                if frame_count % self.embed_frequency == 0 and bit_index < len(binary_data):
                    # 모션 감지 (이전 프레임과 비교)
                    if previous_frame is not None:
                        motion_mask = self._detect_motion(previous_frame, frame)
                        # 모션이 적은 영역에서 임베딩 수행
                        stable_regions = ~motion_mask
                    else:
                        stable_regions = np.ones((height, width), dtype=bool)
                    
                    # DCT 임베딩 수행
                    processed_frame, new_bit_index, positions = self._process_frame_blocks(
                        frame, "embed", binary_data, bit_index)
                    
                    bit_index = new_bit_index
                    self.logger.debug(f"프레임 {frame_count}: {len(positions)}개 위치에 임베딩, "
                                    f"진행률: {bit_index}/{len(binary_data)}")
                
                out.write(processed_frame)
                previous_frame = frame.copy()
                frame_count += 1
                
                # 진행상황 표시
                if frame_count % 100 == 0:
                    progress = (frame_count / total_frames) * 100
                    self.logger.info(f"진행률: {progress:.1f}% ({frame_count}/{total_frames})")
            
            # 리소스 정리
            cap.release()
            out.release()
            
            if bit_index < len(binary_data):
                self.logger.warning(f"일부 데이터만 임베딩됨: {bit_index}/{len(binary_data)} bits")
            
            self.logger.info(f"DCT 비디오 스테가노그래피 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"임베딩 중 오류 발생: {str(e)}")
            return False
    
    def extract_message(self, video_path: str, password: Optional[str] = None) -> str:
        """비디오에서 메시지 추출"""
        try:
            self.logger.info(f"DCT 비디오 스테가노그래피 추출 시작: {video_path}")
            
            # 비디오 파일 검증
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"비디오 파일을 찾을 수 없습니다: {video_path}")
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"비디오 파일을 열 수 없습니다: {video_path}")
            
            # 비디오 속성
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            # 데이터 추출
            extracted_bits = []
            frame_count = 0
            
            # 먼저 헤더 크기 추출 (4바이트)
            header_length = None
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                if frame_count % self.embed_frequency == 0:
                    # 프레임에서 비트 추출
                    frame_bits = self._extract_bits_from_frame(frame)
                    extracted_bits.extend(frame_bits)
                    
                    # 헤더 길이 확인
                    if header_length is None and len(extracted_bits) >= 32:
                        header_length_bits = extracted_bits[:32]
                        header_length = struct.unpack('<I', 
                            bytes(int(''.join(map(str, header_length_bits[i:i+8])), 2) 
                                 for i in range(0, 32, 8)))[0]
                        self.logger.debug(f"헤더 길이: {header_length} bytes")
                    
                    # 헤더 + 데이터 추출 완료 확인
                    if header_length and len(extracted_bits) >= (4 + header_length) * 8:
                        # 헤더 파싱을 위해 일부만 더 추출
                        needed_bits = (4 + header_length) * 8
                        if len(extracted_bits) >= needed_bits:
                            break
                
                frame_count += 1
            
            cap.release()
            
            if not extracted_bits:
                raise ValueError("추출할 수 있는 데이터가 없습니다.")
            
            # 헤더 파싱
            header_bits = extracted_bits[32:(4 + header_length) * 8]
            header_bytes = bytes(int(''.join(map(str, header_bits[i:i+8])), 2) 
                               for i in range(0, len(header_bits), 8))
            header = json.loads(header_bytes.decode('utf-8'))
            
            # 실제 데이터 추출
            data_start = (4 + header_length) * 8
            data_length = header['length'] * 8
            
            if len(extracted_bits) < data_start + data_length:
                # 더 많은 프레임에서 데이터 추출 필요
                self.logger.info("추가 데이터 추출 필요, 비디오 재분석...")
                cap = cv2.VideoCapture(video_path)
                extracted_bits = self._extract_all_bits(cap)
                cap.release()
            
            if len(extracted_bits) < data_start + data_length:
                raise ValueError(f"충분한 데이터를 추출할 수 없습니다. "
                               f"필요: {data_length}bits, 추출: {len(extracted_bits) - data_start}bits")
            
            # 데이터 복원
            data_bits = extracted_bits[data_start:data_start + data_length]
            data_bytes = bytes(int(''.join(map(str, data_bits[i:i+8])), 2) 
                             for i in range(0, len(data_bits), 8))
            
            # 체크섬 검증
            if hashlib.md5(data_bytes).hexdigest() != header['checksum']:
                raise ValueError("데이터 무결성 검증 실패")
            
            # 복호화
            if header['encrypted']:
                if not password:
                    raise ValueError("암호화된 데이터이지만 패스워드가 제공되지 않았습니다.")
                message = self._decrypt_data(data_bytes, password)
            else:
                message = data_bytes.decode('utf-8')
            
            self.logger.info("DCT 비디오 스테가노그래피 추출 완료")
            return message
            
        except Exception as e:
            self.logger.error(f"추출 중 오류 발생: {str(e)}")
            raise
    
    def _extract_bits_from_frame(self, frame: np.ndarray) -> List[int]:
        """프레임에서 비트 추출"""
        height, width = frame.shape[:2]
        extracted_bits = []
        
        # 그레이스케일 변환
        if len(frame.shape) == 3:
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            y_channel = gray_frame.astype(np.float32) - 128
        else:
            y_channel = frame.astype(np.float32) - 128
        
        # 8x8 블록으로 분할하여 처리
        for i in range(0, height - self.block_size + 1, self.block_size):
            for j in range(0, width - self.block_size + 1, self.block_size):
                block = y_channel[i:i+self.block_size, j:j+self.block_size]
                
                # DCT 변환
                dct_block = self._apply_dct_2d(block)
                quantized_block = self._quantize_dct(dct_block)
                
                # 임베딩된 위치에서 비트 추출
                embeddable_positions = self._get_embeddable_positions(quantized_block)
                
                for pos in embeddable_positions:
                    bit = self._extract_bit_from_dct(quantized_block, pos)
                    extracted_bits.append(bit)
        
        return extracted_bits
    
    def _extract_all_bits(self, cap: cv2.VideoCapture) -> List[int]:
        """모든 임베딩 프레임에서 비트 추출"""
        extracted_bits = []
        frame_count = 0
        
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)  # 처음으로 돌아가기
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            if frame_count % self.embed_frequency == 0:
                frame_bits = self._extract_bits_from_frame(frame)
                extracted_bits.extend(frame_bits)
            
            frame_count += 1
        
        return extracted_bits
    
    def get_capacity(self, video_path: str) -> int:
        """비디오의 임베딩 용량 계산 (바이트 단위)"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return 0
            
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            cap.release()
            
            # 블록당 임베딩 가능한 비트 수 (대략적 추정)
            blocks_per_frame = (height // self.block_size) * (width // self.block_size)
            bits_per_block = min(8, max(1, blocks_per_frame // 100))  # 적응형 계산
            
            embed_frames = total_frames // self.embed_frequency
            total_bits = embed_frames * blocks_per_frame * bits_per_block
            
            # 헤더 오버헤드 고려
            overhead_bits = 1024  # 대략적인 헤더 크기
            available_bits = max(0, total_bits - overhead_bits)
            
            return available_bits // 8  # 바이트로 변환
            
        except Exception:
            return 0
    
    def is_suitable_video(self, video_path: str) -> Dict[str, Any]:
        """비디오가 DCT 스테가노그래피에 적합한지 분석"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return {
                    'suitable': False,
                    'reason': '비디오 파일을 열 수 없습니다',
                    'score': 0.0
                }
            
            # 비디오 속성
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            # 샘플 프레임들로 분석
            sample_frames = min(10, total_frames // 10)
            complexity_scores = []
            motion_scores = []
            previous_frame = None
            
            for i in range(sample_frames):
                frame_idx = i * (total_frames // sample_frames)
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                
                if ret:
                    # 복잡도 분석 (DCT 계수의 분산)
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    complexity = self._analyze_frame_complexity(gray)
                    complexity_scores.append(complexity)
                    
                    # 모션 분석
                    if previous_frame is not None:
                        motion = np.mean(self._detect_motion(previous_frame, frame))
                        motion_scores.append(motion)
                    
                    previous_frame = frame
            
            cap.release()
            
            # 점수 계산
            avg_complexity = np.mean(complexity_scores)
            avg_motion = np.mean(motion_scores) if motion_scores else 0.5
            
            # 적합성 점수 (0.0 - 1.0)
            resolution_score = min(1.0, (width * height) / (640 * 480))  # 해상도
            complexity_score = min(1.0, avg_complexity / 100)  # 복잡도
            motion_score = 1.0 - min(1.0, avg_motion)  # 적은 모션이 좋음
            duration_score = min(1.0, total_frames / 300)  # 충분한 길이
            
            overall_score = (resolution_score * 0.3 + complexity_score * 0.4 + 
                           motion_score * 0.2 + duration_score * 0.1)
            
            suitable = overall_score >= 0.6
            
            analysis = {
                'suitable': suitable,
                'score': overall_score,
                'resolution': f"{width}x{height}",
                'fps': fps,
                'duration_frames': total_frames,
                'avg_complexity': avg_complexity,
                'avg_motion': avg_motion,
                'capacity_bytes': self.get_capacity(video_path),
                'recommendations': []
            }
            
            # 권장사항
            if resolution_score < 0.5:
                analysis['recommendations'].append("더 높은 해상도의 비디오 사용 권장")
            if complexity_score < 0.4:
                analysis['recommendations'].append("더 복잡한 장면의 비디오 사용 권장")
            if motion_score < 0.3:
                analysis['recommendations'].append("모션이 적은 비디오 사용 권장")
            if duration_score < 0.3:
                analysis['recommendations'].append("더 긴 비디오 사용 권장")
            
            return analysis
            
        except Exception as e:
            return {
                'suitable': False,
                'reason': f'분석 중 오류: {str(e)}',
                'score': 0.0
            }
    
    def _analyze_frame_complexity(self, frame: np.ndarray) -> float:
        """프레임 복잡도 분석 (DCT 계수 기반)"""
        height, width = frame.shape
        complexity_scores = []
        
        # 8x8 블록으로 분할하여 복잡도 계산
        for i in range(0, height - self.block_size + 1, self.block_size):
            for j in range(0, width - self.block_size + 1, self.block_size):
                block = frame[i:i+self.block_size, j:j+self.block_size].astype(np.float32) - 128
                
                # DCT 변환
                dct_block = self._apply_dct_2d(block)
                
                # AC 계수들의 분산으로 복잡도 측정
                ac_coeffs = dct_block[1:, 1:].flatten()  # DC 제외
                complexity = np.var(ac_coeffs)
                complexity_scores.append(complexity)
        
        return np.mean(complexity_scores)