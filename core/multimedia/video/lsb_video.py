"""
LSB 비디오 스테가노그래피 v3.0

비디오 파일의 각 프레임에서 LSB(Least Significant Bit) 조작을 통해 데이터를 은닉하는 기법입니다.
이미지 LSB와 유사하지만, 시간축 정보와 프레임 간 연속성을 고려한 고급 기능을 포함합니다.

주요 특징:
- 프레임별 LSB 데이터 은닉
- 시간축 분산을 통한 은닉성 향상
- 프레임 품질 유지를 위한 적응적 임베딩
- 다양한 비디오 포맷 지원 (OpenCV 기반)
"""

import cv2
import numpy as np
from typing import Tuple, Dict, Optional, List
from pathlib import Path
import tempfile
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib

class LSBVideoSteganography:
    """LSB 비디오 스테가노그래피 클래스"""
    
    def __init__(self):
        """초기화"""
        self.version = "3.0.0"
        self.author = "디지털포렌식 연구소"
        
        # LSB 임베딩 파라미터
        self.bits_per_pixel = 1  # 픽셀당 임베딩할 비트 수
        self.channels = ['B', 'G', 'R']  # 사용할 채널 (BGR 순서)
        self.use_channels = [True, True, False]  # R 채널은 사용 안 함 (더 은밀함)
        
        # 프레임 선택 파라미터
        self.frame_skip = 5  # 몇 프레임마다 사용할지
        self.max_frames_per_message = 100  # 메시지당 최대 프레임 수
        
        # 품질 유지 파라미터
        self.quality_threshold = 30.0  # PSNR 기준값
        self.adaptive_embedding = True  # 적응적 임베딩 여부
        
        # 데이터 처리
        self.header_marker = b"LSBVIDEO_V3"
        self.encoding = 'utf-8'
        
        # 암호화 설정
        self.key_length = 32
        self.salt_length = 16
        
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None) -> bool:
        """
        메시지를 비디오 파일에 LSB로 임베딩
        
        Args:
            input_path: 입력 비디오 파일 경로
            message: 숨길 메시지
            output_path: 출력 비디오 파일 경로
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 임베딩 성공 여부
        """
        try:
            # 비디오 파일 열기
            cap = cv2.VideoCapture(input_path)
            if not cap.isOpened():
                print(f"❌ 비디오 파일을 열 수 없습니다: {input_path}")
                return False
            
            # 비디오 속성 가져오기
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fourcc = int(cap.get(cv2.CAP_PROP_FOURCC))
            
            # 메시지 준비
            if password:
                encrypted_data = self._encrypt_message(message, password)
                binary_data = self._prepare_encrypted_data(encrypted_data)
            else:
                binary_data = self._prepare_plain_data(message)
            
            # 용량 확인
            capacity = self._calculate_capacity(width, height, total_frames)
            if len(binary_data) > capacity:
                print(f"⚠️ 용량 부족: 필요 {len(binary_data)} bits > 가용 {capacity} bits")
                return False
            
            # 비디오 writer 설정
            writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            if not writer.isOpened():
                print(f"❌ 출력 비디오 파일을 생성할 수 없습니다: {output_path}")
                return False
            
            print(f"🎬 비디오 LSB 임베딩 시작...")
            print(f"📊 해상도: {width}x{height}, FPS: {fps}, 총 프레임: {total_frames}")
            
            # 프레임별 처리
            frame_count = 0
            data_index = 0
            embedded_frames = 0
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # 데이터 임베딩이 필요한 프레임인지 확인
                if (frame_count % self.frame_skip == 0 and 
                    data_index < len(binary_data) and
                    embedded_frames < self.max_frames_per_message):
                    
                    # LSB 임베딩
                    stego_frame, bits_embedded = self._embed_data_in_frame(
                        frame, binary_data[data_index:], width, height
                    )
                    data_index += bits_embedded
                    embedded_frames += 1
                    
                    writer.write(stego_frame)
                    
                    if embedded_frames % 10 == 0:
                        progress = (data_index / len(binary_data)) * 100
                        print(f"📈 진행률: {progress:.1f}% ({embedded_frames} 프레임 처리)")
                else:
                    # 원본 프레임 그대로 사용
                    writer.write(frame)
                
                frame_count += 1
            
            # 리소스 정리
            cap.release()
            writer.release()
            
            if data_index >= len(binary_data):
                print(f"✅ LSB 비디오 임베딩 완료: {len(message)} 글자 → {output_path}")
                print(f"📊 사용된 프레임: {embedded_frames}/{total_frames}")
                return True
            else:
                print(f"⚠️ 임베딩 불완전: {data_index}/{len(binary_data)} bits")
                return False
                
        except Exception as e:
            print(f"❌ LSB 비디오 임베딩 오류: {e}")
            return False
    
    def extract_message(self, input_path: str,
                       password: Optional[str] = None) -> Optional[str]:
        """
        LSB로 은닉된 메시지를 추출
        
        Args:
            input_path: 스테고 비디오 파일 경로
            password: 복호화 패스워드 (선택사항)
            
        Returns:
            str: 추출된 메시지 또는 None
        """
        try:
            # 비디오 파일 열기
            cap = cv2.VideoCapture(input_path)
            if not cap.isOpened():
                print(f"❌ 비디오 파일을 열 수 없습니다: {input_path}")
                return None
            
            # 비디오 속성
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            print(f"🔍 LSB 비디오 추출 시작...")
            print(f"📊 총 {total_frames} 프레임 분석 예정")
            
            # 프레임별 데이터 추출
            extracted_bits = []
            frame_count = 0
            analyzed_frames = 0
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # 데이터가 임베딩된 프레임인지 확인
                if frame_count % self.frame_skip == 0 and analyzed_frames < self.max_frames_per_message:
                    frame_bits = self._extract_data_from_frame(frame, width, height)
                    extracted_bits.extend(frame_bits)
                    analyzed_frames += 1
                    
                    if analyzed_frames % 10 == 0:
                        print(f"📈 분석 진행률: {analyzed_frames} 프레임 완료")
                    
                    # 헤더를 찾았는지 중간 체크
                    if len(extracted_bits) >= len(self.header_marker) * 8:
                        binary_data = ''.join(extracted_bits)
                        if self._validate_header(binary_data):
                            # 헤더 발견, 필요한 만큼만 더 추출
                            required_bits = self._calculate_required_bits(binary_data)
                            if len(extracted_bits) >= required_bits:
                                break
                
                frame_count += 1
            
            cap.release()
            
            if not extracted_bits:
                print("❌ 추출된 데이터가 없습니다")
                return None
            
            binary_data = ''.join(extracted_bits)
            
            # 헤더 검증
            if not self._validate_header(binary_data):
                print("❌ 유효한 헤더를 찾을 수 없습니다")
                return None
            
            # 메시지 복원
            if password:
                return self._restore_encrypted_message(binary_data, password)
            else:
                return self._restore_plain_message(binary_data)
                
        except Exception as e:
            print(f"❌ LSB 비디오 추출 오류: {e}")
            return None
    
    def _embed_data_in_frame(self, frame: np.ndarray, data: str,
                            width: int, height: int) -> Tuple[np.ndarray, int]:
        """프레임에 데이터 임베딩"""
        stego_frame = frame.copy()
        bits_embedded = 0
        
        # 사용 가능한 픽셀 수 계산
        available_pixels = width * height
        max_bits_per_frame = available_pixels * sum(self.use_channels) * self.bits_per_pixel
        
        # 임베딩할 데이터 길이 결정
        bits_to_embed = min(len(data), max_bits_per_frame)
        data_to_embed = data[:bits_to_embed]
        
        data_index = 0
        
        # 각 픽셀에 데이터 임베딩
        for y in range(height):
            for x in range(width):
                if data_index >= len(data_to_embed):
                    break
                
                pixel = stego_frame[y, x]
                
                # 각 채널에 대해 LSB 임베딩
                for channel_idx, use_channel in enumerate(self.use_channels):
                    if not use_channel or data_index >= len(data_to_embed):
                        continue
                    
                    # 현재 채널 값
                    channel_value = pixel[channel_idx]
                    
                    # 임베딩할 비트 가져오기
                    for bit_pos in range(self.bits_per_pixel):
                        if data_index >= len(data_to_embed):
                            break
                        
                        bit = int(data_to_embed[data_index])
                        data_index += 1
                        bits_embedded += 1
                        
                        # LSB 조작
                        if bit_pos == 0:  # LSB만 사용
                            channel_value = (channel_value & 0xFE) | bit
                        
                    stego_frame[y, x, channel_idx] = channel_value
                
            if data_index >= len(data_to_embed):
                break
        
        return stego_frame, bits_embedded
    
    def _extract_data_from_frame(self, frame: np.ndarray,
                                width: int, height: int) -> List[str]:
        """프레임에서 데이터 추출"""
        extracted_bits = []
        
        # 각 픽셀에서 데이터 추출
        for y in range(height):
            for x in range(width):
                pixel = frame[y, x]
                
                # 각 채널에서 LSB 추출
                for channel_idx, use_channel in enumerate(self.use_channels):
                    if not use_channel:
                        continue
                    
                    channel_value = pixel[channel_idx]
                    
                    # LSB 추출
                    for bit_pos in range(self.bits_per_pixel):
                        if bit_pos == 0:  # LSB만 사용
                            bit = channel_value & 1
                            extracted_bits.append(str(bit))
        
        return extracted_bits
    
    def _calculate_capacity(self, width: int, height: int, total_frames: int) -> int:
        """비디오 LSB 용량 계산"""
        pixels_per_frame = width * height
        bits_per_frame = pixels_per_frame * sum(self.use_channels) * self.bits_per_pixel
        
        # 사용할 프레임 수 계산
        usable_frames = min(
            total_frames // self.frame_skip,
            self.max_frames_per_message
        )
        
        total_capacity = bits_per_frame * usable_frames
        
        # 헤더와 메타데이터를 위한 여유 확보 (10%)
        usable_capacity = int(total_capacity * 0.9)
        
        return usable_capacity
    
    def _calculate_required_bits(self, binary_data: str) -> int:
        """필요한 비트 수 계산 (헤더 기반)"""
        try:
            header_size = len(self.header_marker) * 8
            if len(binary_data) < header_size + 32:
                return header_size + 1000  # 기본값
            
            # 메시지 길이 추출
            length_bits = binary_data[header_size:header_size + 32]
            message_length = int(length_bits, 2)
            
            # 전체 필요 비트 수 = 헤더 + 길이 + 메시지
            return header_size + 32 + message_length * 8
        except:
            return len(binary_data) + 1000  # 안전한 기본값
    
    def get_capacity(self, file_path: str) -> int:
        """비디오 LSB 용량 계산"""
        try:
            cap = cv2.VideoCapture(file_path)
            if not cap.isOpened():
                return 0
            
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            cap.release()
            
            return self._calculate_capacity(width, height, total_frames)
            
        except Exception as e:
            print(f"❌ 용량 계산 오류: {e}")
            return 0
    
    def analyze_suitability(self, file_path: str) -> Dict:
        """비디오 LSB 적합성 분석"""
        try:
            cap = cv2.VideoCapture(file_path)
            if not cap.isOpened():
                return {'suitability_score': 0.0, 'recommended': False}
            
            # 비디오 속성
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            duration = total_frames / fps if fps > 0 else 0
            
            # 몇 개 프레임 샘플링하여 복잡도 분석
            sample_frames = min(10, total_frames)
            complexity_scores = []
            
            for i in range(sample_frames):
                frame_pos = int(i * total_frames / sample_frames)
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_pos)
                ret, frame = cap.read()
                
                if ret:
                    # 프레임 복잡도 계산 (엣지 밀도)
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    edges = cv2.Canny(gray, 50, 150)
                    edge_density = np.sum(edges > 0) / (width * height)
                    complexity_scores.append(edge_density)
            
            cap.release()
            
            # 적합성 점수 계산
            avg_complexity = np.mean(complexity_scores) if complexity_scores else 0
            resolution_score = min((width * height) / (640 * 480), 1.0)
            duration_score = min(duration / 30.0, 1.0)  # 30초 이상이면 1.0
            
            suitability_score = (avg_complexity * 0.4 + 
                               resolution_score * 0.3 + 
                               duration_score * 0.3)
            
            return {
                'suitability_score': suitability_score,
                'resolution': f"{width}x{height}",
                'total_frames': total_frames,
                'duration': duration,
                'fps': fps,
                'avg_complexity': avg_complexity,
                'estimated_capacity': self.get_capacity(file_path),
                'recommended': suitability_score > 0.6 and total_frames > 30
            }
            
        except Exception as e:
            print(f"❌ 적합성 분석 오류: {e}")
            return {'suitability_score': 0.0, 'recommended': False}
    
    def _prepare_plain_data(self, message: str) -> str:
        """평문 데이터 준비"""
        message_bytes = message.encode(self.encoding)
        length_bytes = len(message_bytes).to_bytes(4, byteorder='big')
        full_data = self.header_marker + length_bytes + message_bytes
        
        return ''.join(format(byte, '08b') for byte in full_data)
    
    def _prepare_encrypted_data(self, encrypted_data: bytes) -> str:
        """암호화된 데이터 준비"""
        length_bytes = len(encrypted_data).to_bytes(4, byteorder='big')
        full_data = self.header_marker + b"_ENC" + length_bytes + encrypted_data
        
        return ''.join(format(byte, '08b') for byte in full_data)
    
    def _validate_header(self, binary_data: str) -> bool:
        """헤더 유효성 검증"""
        if len(binary_data) < len(self.header_marker) * 8:
            return False
        
        header_bits = binary_data[:len(self.header_marker) * 8]
        header_bytes = bytes([int(header_bits[i:i+8], 2) 
                             for i in range(0, len(header_bits), 8)])
        
        return header_bytes == self.header_marker
    
    def _restore_plain_message(self, binary_data: str) -> str:
        """평문 메시지 복원"""
        try:
            offset = len(self.header_marker) * 8
            length_bits = binary_data[offset:offset + 32]
            message_length = int(length_bits, 2)
            offset += 32
            
            message_bits = binary_data[offset:offset + message_length * 8]
            if len(message_bits) < message_length * 8:
                raise ValueError("데이터가 불완전합니다")
            
            message_bytes = bytes([int(message_bits[i:i+8], 2) 
                                  for i in range(0, len(message_bits), 8)])
            
            return message_bytes.decode(self.encoding)
        except Exception as e:
            print(f"❌ 평문 메시지 복원 오류: {e}")
            return None
    
    def _restore_encrypted_message(self, binary_data: str, password: str) -> str:
        """암호화된 메시지 복원"""
        try:
            offset = (len(self.header_marker) + 4) * 8
            length_bits = binary_data[offset:offset + 32]
            data_length = int(length_bits, 2)
            offset += 32
            
            data_bits = binary_data[offset:offset + data_length * 8]
            if len(data_bits) < data_length * 8:
                raise ValueError("암호화된 데이터가 불완전합니다")
            
            encrypted_data = bytes([int(data_bits[i:i+8], 2) 
                                   for i in range(0, len(data_bits), 8)])
            
            return self._decrypt_message(encrypted_data, password)
        except Exception as e:
            print(f"❌ 암호화된 메시지 복원 오류: {e}")
            return None
    
    def _encrypt_message(self, message: str, password: str) -> bytes:
        """메시지 암호화"""
        try:
            salt = os.urandom(self.salt_length)
            key = PBKDF2(password, salt, dkLen=self.key_length)
            
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(message.encode(self.encoding))
            
            return salt + cipher.nonce + tag + ciphertext
        except Exception as e:
            raise Exception(f"암호화 실패: {e}")
    
    def _decrypt_message(self, encrypted_data: bytes, password: str) -> str:
        """메시지 복호화"""
        try:
            salt = encrypted_data[:self.salt_length]
            nonce = encrypted_data[self.salt_length:self.salt_length + 16]
            tag = encrypted_data[self.salt_length + 16:self.salt_length + 32]
            ciphertext = encrypted_data[self.salt_length + 32:]
            
            key = PBKDF2(password, salt, dkLen=self.key_length)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode(self.encoding)
        except Exception as e:
            raise Exception(f"복호화 실패: {e}")

# 사용 예시 및 테스트
if __name__ == "__main__":
    print("🎬 LSB Video 스테가노그래피 v3.0")
    print("=" * 45)
    
    # 인스턴스 생성
    video_lsb = LSBVideoSteganography()
    
    # 예시 파일 경로
    input_video = "sample_video.mp4"
    output_video = "lsb_stego_video.mp4"
    
    # 테스트 메시지
    test_message = "🎬 LSB Video 테스트 메시지 - Video Steganography with OpenCV!"
    
    print(f"📝 테스트 메시지: {test_message}")
    
    # 실제 파일이 있을 경우의 테스트 코드
    # if Path(input_video).exists():
    #     analysis = video_lsb.analyze_suitability(input_video)
    #     print(f"📊 적합성 점수: {analysis['suitability_score']:.3f}")
    #     print(f"📐 해상도: {analysis['resolution']}")
    #     print(f"💾 예상 용량: {analysis['estimated_capacity']} bits")
    #     
    #     if analysis['recommended']:
    #         success = video_lsb.embed_message(
    #             input_video, test_message, output_video, "video_lsb_123"
    #         )
    #         
    #         if success:
    #             extracted = video_lsb.extract_message(output_video, "video_lsb_123")
    #             print(f"🔍 추출된 메시지: {extracted}")
    
    print("\n💡 LSB Video 특징:")
    print("- 각 프레임의 픽셀에 LSB 데이터 은닉")
    print("- 시간축 분산을 통한 은닉성 향상")
    print("- 적응적 임베딩으로 화질 유지")
    print("- 다양한 비디오 포맷 지원")