"""
Motion Vector Steganography v3.0
디지털 포렌식 연구소

모션 벡터 기반 비디오 스테가노그래피 구현
비디오 압축의 모션 보상 과정에서 생성되는 모션 벡터를 조작하여 데이터를 은닉합니다.

주요 특징:
- H.264/H.265 모션 벡터 조작
- 시각적 품질 최소 손실
- 압축 효율성 유지
- 인트라/인터 프레임 분석
- 적응형 벡터 선택
"""

import cv2
import numpy as np
import os
import hashlib
from typing import Tuple, Optional, List, Dict, Any, Union
from pathlib import Path
import struct
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import logging
from scipy import ndimage
from sklearn.cluster import KMeans

class MotionVectorSteganography:
    """모션 벡터 기반 비디오 스테가노그래피 클래스"""
    
    def __init__(self,
                 block_size: int = 16,
                 search_range: int = 16,
                 threshold_similarity: float = 0.95,
                 motion_threshold: float = 2.0,
                 vector_precision: int = 2,
                 max_distortion: float = 1.0):
        """
        Motion Vector Steganography 초기화
        
        Args:
            block_size: 모션 추정 블록 크기 (일반적으로 16x16)
            search_range: 모션 벡터 검색 범위
            threshold_similarity: 블록 유사도 임계값
            motion_threshold: 모션 감지 임계값
            vector_precision: 벡터 정밀도 (소수점 자릿수)
            max_distortion: 최대 허용 왜곡
        """
        self.block_size = block_size
        self.search_range = search_range
        self.threshold_similarity = threshold_similarity
        self.motion_threshold = motion_threshold
        self.vector_precision = vector_precision
        self.max_distortion = max_distortion
        
        # 로깅 설정
        self.logger = logging.getLogger(__name__)
        
        # 모션 벡터 조작 패턴
        self.embed_patterns = {
            0: (0, 0),    # 비트 0: 벡터 변화 없음
            1: (1, 1),    # 비트 1: 미세한 벡터 조정
        }
        
        # 품질 보존을 위한 가중치
        self.quality_weights = {
            'edge': 0.3,      # 엣지 영역 가중치
            'texture': 0.4,   # 텍스처 영역 가중치
            'smooth': 0.8,    # 평활 영역 가중치
        }
    
    def _calculate_sad(self, block1: np.ndarray, block2: np.ndarray) -> float:
        """Sum of Absolute Differences 계산"""
        return np.sum(np.abs(block1.astype(np.float32) - block2.astype(np.float32)))
    
    def _calculate_mse(self, block1: np.ndarray, block2: np.ndarray) -> float:
        """Mean Square Error 계산"""
        return np.mean((block1.astype(np.float32) - block2.astype(np.float32)) ** 2)
    
    def _block_matching(self, current_frame: np.ndarray, reference_frame: np.ndarray,
                       block_row: int, block_col: int) -> Tuple[int, int, float]:
        """블록 매칭을 통한 모션 벡터 계산"""
        min_sad = float('inf')
        best_mv = (0, 0)
        
        # 현재 블록
        current_block = current_frame[
            block_row:block_row + self.block_size,
            block_col:block_col + self.block_size
        ]
        
        # 검색 범위 내에서 최적 매칭 블록 찾기
        for dy in range(-self.search_range, self.search_range + 1):
            for dx in range(-self.search_range, self.search_range + 1):
                ref_row = block_row + dy
                ref_col = block_col + dx
                
                # 경계 검사
                if (ref_row < 0 or ref_col < 0 or 
                    ref_row + self.block_size > reference_frame.shape[0] or
                    ref_col + self.block_size > reference_frame.shape[1]):
                    continue
                
                # 참조 블록
                ref_block = reference_frame[
                    ref_row:ref_row + self.block_size,
                    ref_col:ref_col + self.block_size
                ]
                
                # SAD 계산
                sad = self._calculate_sad(current_block, ref_block)
                
                if sad < min_sad:
                    min_sad = sad
                    best_mv = (dx, dy)
        
        return best_mv[0], best_mv[1], min_sad
    
    def _get_motion_vectors(self, current_frame: np.ndarray, 
                           reference_frame: np.ndarray) -> List[Dict]:
        """프레임 간 모션 벡터 계산"""
        height, width = current_frame.shape
        motion_vectors = []
        
        for row in range(0, height - self.block_size + 1, self.block_size):
            for col in range(0, width - self.block_size + 1, self.block_size):
                mv_x, mv_y, sad = self._block_matching(
                    current_frame, reference_frame, row, col)
                
                motion_vectors.append({
                    'position': (row, col),
                    'vector': (mv_x, mv_y),
                    'sad': sad,
                    'magnitude': np.sqrt(mv_x**2 + mv_y**2)
                })
        
        return motion_vectors
    
    def _analyze_block_characteristics(self, block: np.ndarray) -> Dict[str, float]:
        """블록의 특성 분석 (엣지, 텍스처, 평활도)"""
        # 엣지 강도 (Sobel 연산자)
        sobel_x = cv2.Sobel(block, cv2.CV_64F, 1, 0, ksize=3)
        sobel_y = cv2.Sobel(block, cv2.CV_64F, 0, 1, ksize=3)
        edge_magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
        edge_strength = np.mean(edge_magnitude)
        
        # 텍스처 복잡도 (Local Binary Pattern 기반)
        texture_complexity = np.std(block)
        
        # 평활도 (분산 기반)
        smoothness = 1.0 / (1.0 + np.var(block))
        
        return {
            'edge_strength': edge_strength,
            'texture_complexity': texture_complexity,
            'smoothness': smoothness
        }
    
    def _select_suitable_vectors(self, motion_vectors: List[Dict], 
                                current_frame: np.ndarray) -> List[int]:
        """데이터 임베딩에 적합한 모션 벡터 선택"""
        suitable_indices = []
        
        for i, mv in enumerate(motion_vectors):
            row, col = mv['position']
            
            # 현재 블록 추출
            block = current_frame[row:row + self.block_size, 
                                col:col + self.block_size]
            
            # 블록 특성 분석
            characteristics = self._analyze_block_characteristics(block)
            
            # 적합성 점수 계산
            suitability_score = (
                characteristics['edge_strength'] * self.quality_weights['edge'] +
                characteristics['texture_complexity'] * self.quality_weights['texture'] +
                characteristics['smoothness'] * self.quality_weights['smooth']
            )
            
            # 모션 벡터 크기와 SAD 고려
            motion_factor = min(1.0, mv['magnitude'] / 5.0)  # 적당한 모션
            quality_factor = 1.0 / (1.0 + mv['sad'] / 1000.0)  # 낮은 SAD 선호
            
            final_score = suitability_score * motion_factor * quality_factor
            
            # 임계값 이상인 벡터 선택
            if final_score > 0.3:
                suitable_indices.append(i)
        
        return suitable_indices
    
    def _modify_motion_vector(self, original_mv: Tuple[int, int], bit: int,
                            modification_strength: float = 1.0) -> Tuple[int, int]:
        """모션 벡터 수정"""
        dx, dy = original_mv
        
        if bit == 1:
            # 비트 1: 벡터에 미세한 변화 추가
            if abs(dx) > abs(dy):
                # x 방향이 더 큰 경우
                new_dx = dx + int(modification_strength) if dx >= 0 else dx - int(modification_strength)
                new_dy = dy
            else:
                # y 방향이 더 큰 경우
                new_dx = dx
                new_dy = dy + int(modification_strength) if dy >= 0 else dy - int(modification_strength)
        else:
            # 비트 0: 원본 유지 또는 미세한 감소
            new_dx = dx
            new_dy = dy
        
        # 검색 범위를 벗어나지 않도록 제한
        new_dx = max(-self.search_range, min(self.search_range, new_dx))
        new_dy = max(-self.search_range, min(self.search_range, new_dy))
        
        return new_dx, new_dy
    
    def _extract_bit_from_vector(self, modified_mv: Tuple[int, int], 
                                original_mv: Tuple[int, int]) -> int:
        """수정된 모션 벡터에서 비트 추출"""
        mdx, mdy = modified_mv
        odx, ody = original_mv
        
        # 벡터 변화량 계산
        change_magnitude = np.sqrt((mdx - odx)**2 + (mdy - ody)**2)
        
        # 변화량이 임계값 이상이면 비트 1, 아니면 비트 0
        return 1 if change_magnitude > 0.5 else 0
    
    def _apply_motion_compensation(self, current_frame: np.ndarray,
                                 reference_frame: np.ndarray,
                                 motion_vectors: List[Dict]) -> np.ndarray:
        """모션 보상 적용"""
        compensated_frame = np.zeros_like(current_frame)
        height, width = current_frame.shape
        
        block_idx = 0
        for row in range(0, height - self.block_size + 1, self.block_size):
            for col in range(0, width - self.block_size + 1, self.block_size):
                if block_idx < len(motion_vectors):
                    mv = motion_vectors[block_idx]
                    dx, dy = mv['vector']
                    
                    # 참조 블록 위치
                    ref_row = row + dy
                    ref_col = col + dx
                    
                    # 경계 검사
                    if (ref_row >= 0 and ref_col >= 0 and
                        ref_row + self.block_size <= height and
                        ref_col + self.block_size <= width):
                        
                        # 모션 보상된 블록 복사
                        compensated_frame[row:row + self.block_size,
                                        col:col + self.block_size] = \
                            reference_frame[ref_row:ref_row + self.block_size,
                                          ref_col:ref_col + self.block_size]
                    else:
                        # 경계를 벗어나면 원본 블록 사용
                        compensated_frame[row:row + self.block_size,
                                        col:col + self.block_size] = \
                            current_frame[row:row + self.block_size,
                                        col:col + self.block_size]
                
                block_idx += 1
        
        return compensated_frame
    
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
            self.logger.info(f"모션 벡터 스테가노그래피 임베딩 시작: {video_path}")
            
            # 비디오 파일 검증
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"비디오 파일을 찾을 수 없습니다: {video_path}")
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"비디오 파일을 열 수 없습니다: {video_path}")
            
            # 비디오 속성
            fps = int(cap.get(cv2.CAP_PROP_FPS))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            self.logger.info(f"비디오 정보: {width}x{height}, {fps}fps, {total_frames}프레임")
            
            # 출력 비디오 설정
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            
            # 데이터 준비
            if password:
                encrypted_message = self._encrypt_data(message, password)
                data_to_embed = encrypted_message
            else:
                data_to_embed = message.encode('utf-8')
            
            # 헤더 생성
            header = {
                'length': len(data_to_embed),
                'encrypted': password is not None,
                'checksum': hashlib.md5(data_to_embed).hexdigest(),
                'block_size': self.block_size,
                'search_range': self.search_range
            }
            header_json = json.dumps(header).encode('utf-8')
            
            # 전체 데이터
            header_length = len(header_json)
            full_data = struct.pack('<I', header_length) + header_json + data_to_embed
            binary_data = ''.join(format(byte, '08b') for byte in full_data)
            
            self.logger.info(f"임베딩할 데이터: {len(binary_data)} bits")
            
            # 용량 확인
            blocks_per_frame = ((height // self.block_size) * 
                              (width // self.block_size))
            usable_vectors_per_frame = int(blocks_per_frame * 0.3)  # 30% 사용
            total_capacity = (total_frames - 1) * usable_vectors_per_frame
            
            if len(binary_data) > total_capacity:
                raise ValueError(f"메시지가 너무 큽니다. 필요: {len(binary_data)}bits, "
                               f"사용가능: {total_capacity}bits")
            
            # 프레임 처리
            frame_count = 0
            bit_index = 0
            previous_frame = None
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # 컬러 프레임을 그레이스케일로 변환
                if len(frame.shape) == 3:
                    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                else:
                    gray_frame = frame
                
                processed_frame = frame.copy()
                
                # 첫 번째 프레임은 참조 프레임으로 사용
                if previous_frame is not None and bit_index < len(binary_data):
                    # 모션 벡터 계산
                    motion_vectors = self._get_motion_vectors(gray_frame, previous_frame)
                    
                    # 적합한 벡터 선택
                    suitable_indices = self._select_suitable_vectors(
                        motion_vectors, gray_frame)
                    
                    # 데이터 임베딩
                    embedded_count = 0
                    for idx in suitable_indices:
                        if bit_index >= len(binary_data):
                            break
                        
                        # 비트 추출 및 벡터 수정
                        bit = int(binary_data[bit_index])
                        original_mv = motion_vectors[idx]['vector']
                        
                        # 적응형 수정 강도 계산
                        block_row, block_col = motion_vectors[idx]['position']
                        block = gray_frame[block_row:block_row + self.block_size,
                                         block_col:block_col + self.block_size]
                        characteristics = self._analyze_block_characteristics(block)
                        
                        modification_strength = min(self.max_distortion,
                                                  1.0 - characteristics['smoothness'])
                        
                        # 모션 벡터 수정
                        modified_mv = self._modify_motion_vector(
                            original_mv, bit, modification_strength)
                        
                        motion_vectors[idx]['vector'] = modified_mv
                        bit_index += 1
                        embedded_count += 1
                    
                    # 수정된 모션 벡터로 모션 보상 적용
                    compensated_frame = self._apply_motion_compensation(
                        gray_frame, previous_frame, motion_vectors)
                    
                    # 보상된 프레임을 컬러로 변환 (원본 색상 정보 유지)
                    if len(frame.shape) == 3:
                        # 휘도 채널만 업데이트
                        yuv_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
                        yuv_frame[:, :, 0] = compensated_frame
                        processed_frame = cv2.cvtColor(yuv_frame, cv2.COLOR_YUV2BGR)
                    else:
                        processed_frame = compensated_frame
                    
                    self.logger.debug(f"프레임 {frame_count}: {embedded_count}개 벡터에 임베딩")
                
                out.write(processed_frame)
                previous_frame = gray_frame.copy()
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
            
            self.logger.info(f"모션 벡터 스테가노그래피 임베딩 완료: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"임베딩 중 오류 발생: {str(e)}")
            return False
    
    def extract_message(self, video_path: str, password: Optional[str] = None) -> str:
        """비디오에서 메시지 추출"""
        try:
            self.logger.info(f"모션 벡터 스테가노그래피 추출 시작: {video_path}")
            
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"비디오 파일을 찾을 수 없습니다: {video_path}")
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"비디오 파일을 열 수 없습니다: {video_path}")
            
            # 비디오 속성
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            # 비트 추출
            extracted_bits = []
            frame_count = 0
            previous_frame = None
            
            # 원본 비디오도 필요 (모션 벡터 비교를 위해)
            # 실제 구현에서는 원본 비디오 경로가 별도로 제공되어야 함
            # 여기서는 단순화된 추출 방법 사용
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                if len(frame.shape) == 3:
                    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                else:
                    gray_frame = frame
                
                if previous_frame is not None:
                    # 모션 벡터 계산 (스테고 비디오에서)
                    motion_vectors = self._get_motion_vectors(gray_frame, previous_frame)
                    
                    # 적합한 벡터 위치에서 비트 추출
                    suitable_indices = self._select_suitable_vectors(
                        motion_vectors, gray_frame)
                    
                    # 각 벡터에서 비트 추출 (단순화된 방법)
                    for idx in suitable_indices:
                        mv = motion_vectors[idx]['vector']
                        # 벡터 크기를 기반으로 비트 추정
                        magnitude = np.sqrt(mv[0]**2 + mv[1]**2)
                        bit = 1 if magnitude > self.motion_threshold else 0
                        extracted_bits.append(bit)
                
                previous_frame = gray_frame.copy()
                frame_count += 1
            
            cap.release()
            
            if not extracted_bits:
                raise ValueError("추출할 수 있는 데이터가 없습니다.")
            
            # 헤더 파싱
            if len(extracted_bits) < 32:
                raise ValueError("헤더를 읽기에 충분한 데이터가 없습니다.")
            
            header_length_bits = extracted_bits[:32]
            header_length = struct.unpack('<I', 
                bytes(int(''.join(map(str, header_length_bits[i:i+8])), 2) 
                     for i in range(0, 32, 8)))[0]
            
            # 헤더 추출
            if len(extracted_bits) < (4 + header_length) * 8:
                raise ValueError("헤더를 완전히 추출할 수 없습니다.")
            
            header_bits = extracted_bits[32:(4 + header_length) * 8]
            header_bytes = bytes(int(''.join(map(str, header_bits[i:i+8])), 2) 
                               for i in range(0, len(header_bits), 8))
            header = json.loads(header_bytes.decode('utf-8'))
            
            # 데이터 추출
            data_start = (4 + header_length) * 8
            data_length = header['length'] * 8
            
            if len(extracted_bits) < data_start + data_length:
                raise ValueError(f"충분한 데이터를 추출할 수 없습니다. "
                               f"필요: {data_length}bits, 사용가능: {len(extracted_bits) - data_start}bits")
            
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
            
            self.logger.info("모션 벡터 스테가노그래피 추출 완료")
            return message
            
        except Exception as e:
            self.logger.error(f"추출 중 오류 발생: {str(e)}")
            raise
    
    def get_capacity(self, video_path: str) -> int:
        """비디오의 임베딩 용량 계산"""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return 0
            
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            cap.release()
            
            # 블록당 임베딩 가능한 비트 수
            blocks_per_frame = (height // self.block_size) * (width // self.block_size)
            usable_vectors_per_frame = int(blocks_per_frame * 0.3)  # 30% 사용
            
            # 첫 번째 프레임은 참조용이므로 제외
            usable_frames = max(0, total_frames - 1)
            total_bits = usable_frames * usable_vectors_per_frame
            
            # 헤더 오버헤드 고려
            overhead_bits = 1024
            available_bits = max(0, total_bits - overhead_bits)
            
            return available_bits // 8
            
        except Exception:
            return 0
    
    def is_suitable_video(self, video_path: str) -> Dict[str, Any]:
        """비디오가 모션 벡터 스테가노그래피에 적합한지 분석"""
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
            motion_scores = []
            complexity_scores = []
            previous_frame = None
            
            for i in range(sample_frames):
                frame_idx = i * (total_frames // sample_frames)
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                
                if ret:
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    
                    # 복잡도 분석
                    complexity = np.std(gray)
                    complexity_scores.append(complexity)
                    
                    # 모션 분석
                    if previous_frame is not None:
                        motion_vectors = self._get_motion_vectors(gray, previous_frame)
                        avg_magnitude = np.mean([mv['magnitude'] for mv in motion_vectors])
                        motion_scores.append(avg_magnitude)
                    
                    previous_frame = gray
            
            cap.release()
            
            # 점수 계산
            avg_motion = np.mean(motion_scores) if motion_scores else 0
            avg_complexity = np.mean(complexity_scores)
            
            # 적합성 점수
            resolution_score = min(1.0, (width * height) / (640 * 480))
            motion_score = min(1.0, avg_motion / 10.0)  # 적당한 모션 필요
            complexity_score = min(1.0, avg_complexity / 50.0)
            duration_score = min(1.0, total_frames / 300)
            
            overall_score = (resolution_score * 0.3 + motion_score * 0.4 + 
                           complexity_score * 0.2 + duration_score * 0.1)
            
            suitable = overall_score >= 0.5
            
            return {
                'suitable': suitable,
                'score': overall_score,
                'resolution': f"{width}x{height}",
                'fps': fps,
                'duration_frames': total_frames,
                'avg_motion': avg_motion,
                'avg_complexity': avg_complexity,
                'capacity_bytes': self.get_capacity(video_path),
                'recommendations': self._get_recommendations(overall_score, 
                                                           resolution_score,
                                                           motion_score,
                                                           complexity_score,
                                                           duration_score)
            }
            
        except Exception as e:
            return {
                'suitable': False,
                'reason': f'분석 중 오류: {str(e)}',
                'score': 0.0
            }
    
    def _get_recommendations(self, overall_score: float, resolution_score: float,
                           motion_score: float, complexity_score: float,
                           duration_score: float) -> List[str]:
        """분석 결과에 따른 권장사항 생성"""
        recommendations = []
        
        if resolution_score < 0.5:
            recommendations.append("더 높은 해상도의 비디오 사용 권장 (최소 640x480)")
        
        if motion_score < 0.3:
            recommendations.append("더 많은 모션이 있는 비디오 사용 권장")
        elif motion_score > 0.8:
            recommendations.append("모션이 너무 많아 품질 저하 가능성 - 안정적인 비디오 권장")
        
        if complexity_score < 0.3:
            recommendations.append("더 복잡한 장면의 비디오 사용 권장")
        
        if duration_score < 0.3:
            recommendations.append("더 긴 비디오 사용 권장")
        
        if overall_score < 0.5:
            recommendations.append("모션 벡터 스테가노그래피 대신 다른 방법 고려")
        
        return recommendations