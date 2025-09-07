"""
프레임 삽입(Frame Injection) 비디오 스테가노그래피 v3.0

기존 비디오에 은밀하게 추가 프레임을 삽입하여 데이터를 은닉하는 기법입니다.
삽입된 프레임은 매우 짧은 시간(1-2프레임) 동안만 표시되어 인간의 눈으로는 인지하기 어렵습니다.

주요 특징:
- 서브리미널 프레임 삽입을 통한 데이터 은닉
- 인간의 시각적 인지 한계 활용
- QR 코드나 DataMatrix를 이용한 고밀도 데이터 저장
- 원본 비디오의 자연스러운 흐름 유지
"""

import cv2
import numpy as np
from typing import Tuple, Dict, Optional, List
from pathlib import Path
import qrcode
from pyzbar import pyzbar
import tempfile
import os
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class FrameInjectionSteganography:
    """프레임 삽입 스테가노그래피 클래스"""
    
    def __init__(self):
        """초기화"""
        self.version = "3.0.0"
        self.author = "디지털포렌식 연구소"
        
        # 프레임 삽입 파라미터
        self.injection_interval = 30  # 몇 프레임마다 삽입할지
        self.injection_duration = 1   # 삽입 프레임 지속 시간 (프레임 수)
        self.max_injections = 50     # 최대 삽입 횟수
        
        # QR 코드 설정
        self.qr_size = 200  # QR 코드 크기
        self.qr_error_correct = qrcode.constants.ERROR_CORRECT_M
        self.qr_box_size = 4
        self.qr_border = 2
        
        # 데이터 청킹
        self.chunk_size = 100  # QR 코드당 최대 데이터 크기 (바이트)
        
        # 삽입 프레임 스타일
        self.background_color = (0, 0, 0)  # 검은 배경
        self.blend_alpha = 0.1  # 원본과 블렌딩 정도 (매우 미세)
        
        # 데이터 처리
        self.header_marker = b"FRAMEINJECTION_V3"
        self.encoding = 'utf-8'
        
        # 암호화 설정
        self.key_length = 32
        self.salt_length = 16
        
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None) -> bool:
        """
        메시지를 프레임 삽입으로 비디오에 은닉
        
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
            
            # 메시지 준비 및 청킹
            if password:
                encrypted_data = self._encrypt_message(message, password)
                data_chunks = self._prepare_encrypted_chunks(encrypted_data)
            else:
                data_chunks = self._prepare_plain_chunks(message)
            
            # 용량 확인
            max_injections = min(self.max_injections, total_frames // self.injection_interval)
            if len(data_chunks) > max_injections:
                print(f"⚠️ 용량 부족: 필요 {len(data_chunks)} chunks > 가용 {max_injections} slots")
                return False
            
            # QR 코드 프레임 생성
            qr_frames = []
            for i, chunk in enumerate(data_chunks):
                qr_frame = self._create_qr_frame(chunk, width, height, i, len(data_chunks))
                qr_frames.append(qr_frame)
            
            # 비디오 writer 설정
            writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            if not writer.isOpened():
                print(f"❌ 출력 비디오 파일을 생성할 수 없습니다: {output_path}")
                return False
            
            print(f"📽️ 프레임 삽입 시작...")
            print(f"📊 해상도: {width}x{height}, 총 {len(data_chunks)}개 QR 청크 삽입")
            
            # 프레임별 처리
            frame_count = 0
            qr_index = 0
            injection_positions = []
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # QR 코드 삽입 시점 확인
                if (frame_count % self.injection_interval == 0 and 
                    qr_index < len(qr_frames)):
                    
                    # QR 프레임 삽입
                    qr_frame = qr_frames[qr_index]
                    
                    # 원본 프레임과 미세하게 블렌딩 (은밀성 향상)
                    if self.blend_alpha > 0:
                        blended_frame = cv2.addWeighted(
                            frame, 1 - self.blend_alpha,
                            qr_frame, self.blend_alpha, 0
                        )
                    else:
                        blended_frame = qr_frame
                    
                    writer.write(blended_frame)
                    injection_positions.append(frame_count)
                    qr_index += 1
                    
                    if qr_index % 5 == 0:
                        print(f"📈 진행률: {qr_index}/{len(qr_frames)} QR 코드 삽입 완료")
                else:
                    # 원본 프레임 그대로 사용
                    writer.write(frame)
                
                frame_count += 1
            
            # 리소스 정리
            cap.release()
            writer.release()
            
            print(f"✅ 프레임 삽입 완료: {len(message)} 글자 → {output_path}")
            print(f"📊 삽입 위치: {injection_positions}")
            return True
            
        except Exception as e:
            print(f"❌ 프레임 삽입 오류: {e}")
            return False
    
    def extract_message(self, input_path: str,
                       password: Optional[str] = None) -> Optional[str]:
        """
        프레임 삽입된 메시지를 추출
        
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
            
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            print(f"🔍 프레임 삽입 추출 시작...")
            print(f"📊 총 {total_frames} 프레임 분석")
            
            # QR 코드 검출 및 추출
            found_chunks = {}
            frame_count = 0
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                # QR 코드가 삽입될 수 있는 프레임인지 확인
                if frame_count % self.injection_interval == 0:
                    # QR 코드 디코딩 시도
                    qr_data = self._decode_qr_from_frame(frame)
                    
                    if qr_data:
                        try:
                            # 청크 정보 파싱
                            chunk_info = self._parse_chunk_data(qr_data)
                            if chunk_info:
                                chunk_id = chunk_info['id']
                                found_chunks[chunk_id] = chunk_info
                                print(f"📱 QR 코드 발견: 청크 {chunk_id}/{chunk_info['total']}")
                        except Exception as e:
                            print(f"⚠️ QR 코드 파싱 오류: {e}")
                
                frame_count += 1
                
                if frame_count % 100 == 0:
                    print(f"📈 분석 진행률: {frame_count}/{total_frames} 프레임")
            
            cap.release()
            
            if not found_chunks:
                print("❌ QR 코드를 찾을 수 없습니다")
                return None
            
            # 청크들을 순서대로 조립
            sorted_chunks = sorted(found_chunks.values(), key=lambda x: x['id'])
            
            # 데이터 재구성
            if password:
                return self._restore_encrypted_chunks(sorted_chunks, password)
            else:
                return self._restore_plain_chunks(sorted_chunks)
                
        except Exception as e:
            print(f"❌ 프레임 추출 오류: {e}")
            return None
    
    def _create_qr_frame(self, data: bytes, width: int, height: int,
                        chunk_id: int, total_chunks: int) -> np.ndarray:
        """QR 코드가 포함된 프레임 생성"""
        try:
            # QR 코드 생성
            qr = qrcode.QRCode(
                version=1,
                error_correction=self.qr_error_correct,
                box_size=self.qr_box_size,
                border=self.qr_border,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # QR 이미지 생성
            qr_img = qr.make_image(fill_color="white", back_color="black")
            qr_img = qr_img.resize((self.qr_size, self.qr_size))
            
            # PIL to OpenCV 변환
            qr_array = np.array(qr_img.convert('RGB'))
            qr_bgr = cv2.cvtColor(qr_array, cv2.COLOR_RGB2BGR)
            
            # 배경 프레임 생성
            frame = np.full((height, width, 3), self.background_color, dtype=np.uint8)
            
            # QR 코드를 중앙에 배치
            y_offset = (height - self.qr_size) // 2
            x_offset = (width - self.qr_size) // 2
            
            if (y_offset >= 0 and x_offset >= 0 and
                y_offset + self.qr_size <= height and
                x_offset + self.qr_size <= width):
                frame[y_offset:y_offset + self.qr_size,
                      x_offset:x_offset + self.qr_size] = qr_bgr
            
            # 청크 정보 텍스트 추가 (디버깅용, 매우 작게)
            info_text = f"{chunk_id+1}/{total_chunks}"
            cv2.putText(frame, info_text, (10, 20),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (128, 128, 128), 1)
            
            return frame
            
        except Exception as e:
            print(f"⚠️ QR 프레임 생성 오류: {e}")
            # 빈 프레임 반환
            return np.full((height, width, 3), self.background_color, dtype=np.uint8)
    
    def _decode_qr_from_frame(self, frame: np.ndarray) -> Optional[bytes]:
        """프레임에서 QR 코드 디코딩"""
        try:
            # OpenCV to PIL 변환
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_image = Image.fromarray(frame_rgb)
            
            # QR 코드 디코딩
            decoded_objects = pyzbar.decode(pil_image)
            
            if decoded_objects:
                # 첫 번째 QR 코드 데이터 반환
                return decoded_objects[0].data
            
            return None
            
        except Exception as e:
            # QR 코드 디코딩 실패는 정상적인 상황
            return None
    
    def _prepare_plain_chunks(self, message: str) -> List[bytes]:
        """평문 메시지를 청크로 분할"""
        # 헤더 + 메시지
        message_bytes = message.encode(self.encoding)
        full_data = self.header_marker + len(message_bytes).to_bytes(4, 'big') + message_bytes
        
        # 청크로 분할
        chunks = []
        total_chunks = (len(full_data) + self.chunk_size - 1) // self.chunk_size
        
        for i in range(total_chunks):
            start = i * self.chunk_size
            end = min((i + 1) * self.chunk_size, len(full_data))
            chunk_data = full_data[start:end]
            
            # 청크 헤더 (청크 ID + 총 청크 수 + 실제 데이터)
            chunk_header = f"CHUNK:{i}:{total_chunks}:".encode('ascii')
            chunk = chunk_header + chunk_data
            chunks.append(chunk)
        
        return chunks
    
    def _prepare_encrypted_chunks(self, encrypted_data: bytes) -> List[bytes]:
        """암호화된 데이터를 청크로 분할"""
        # 헤더 + 암호화된 데이터
        full_data = self.header_marker + b"_ENC" + len(encrypted_data).to_bytes(4, 'big') + encrypted_data
        
        # 청크로 분할
        chunks = []
        total_chunks = (len(full_data) + self.chunk_size - 1) // self.chunk_size
        
        for i in range(total_chunks):
            start = i * self.chunk_size
            end = min((i + 1) * self.chunk_size, len(full_data))
            chunk_data = full_data[start:end]
            
            chunk_header = f"CHUNK:{i}:{total_chunks}:".encode('ascii')
            chunk = chunk_header + chunk_data
            chunks.append(chunk)
        
        return chunks
    
    def _parse_chunk_data(self, qr_data: bytes) -> Optional[Dict]:
        """QR 코드에서 청크 데이터 파싱"""
        try:
            # 청크 헤더 파싱
            data_str = qr_data.decode('ascii', errors='ignore')
            
            if not data_str.startswith('CHUNK:'):
                return None
            
            parts = data_str.split(':', 3)
            if len(parts) < 4:
                return None
            
            chunk_id = int(parts[1])
            total_chunks = int(parts[2])
            
            # 실제 데이터 부분
            header_len = len(f"CHUNK:{chunk_id}:{total_chunks}:")
            chunk_data = qr_data[header_len:]
            
            return {
                'id': chunk_id,
                'total': total_chunks,
                'data': chunk_data
            }
            
        except Exception as e:
            return None
    
    def _restore_plain_chunks(self, chunks: List[Dict]) -> Optional[str]:
        """청크들을 조립하여 평문 메시지 복원"""
        try:
            # 청크 데이터 연결
            combined_data = b''.join([chunk['data'] for chunk in chunks])
            
            # 헤더 검증
            if not combined_data.startswith(self.header_marker):
                print("❌ 유효한 헤더를 찾을 수 없습니다")
                return None
            
            # 메시지 길이 추출
            offset = len(self.header_marker)
            message_length = int.from_bytes(combined_data[offset:offset + 4], 'big')
            offset += 4
            
            # 메시지 추출
            message_bytes = combined_data[offset:offset + message_length]
            
            if len(message_bytes) < message_length:
                print("❌ 메시지 데이터가 불완전합니다")
                return None
            
            return message_bytes.decode(self.encoding)
            
        except Exception as e:
            print(f"❌ 평문 청크 복원 오류: {e}")
            return None
    
    def _restore_encrypted_chunks(self, chunks: List[Dict], password: str) -> Optional[str]:
        """청크들을 조립하여 암호화된 메시지 복원"""
        try:
            # 청크 데이터 연결
            combined_data = b''.join([chunk['data'] for chunk in chunks])
            
            # 헤더 검증
            expected_header = self.header_marker + b"_ENC"
            if not combined_data.startswith(expected_header):
                print("❌ 유효한 암호화 헤더를 찾을 수 없습니다")
                return None
            
            # 암호화된 데이터 길이 추출
            offset = len(expected_header)
            data_length = int.from_bytes(combined_data[offset:offset + 4], 'big')
            offset += 4
            
            # 암호화된 데이터 추출
            encrypted_data = combined_data[offset:offset + data_length]
            
            if len(encrypted_data) < data_length:
                print("❌ 암호화된 데이터가 불완전합니다")
                return None
            
            # 복호화
            return self._decrypt_message(encrypted_data, password)
            
        except Exception as e:
            print(f"❌ 암호화된 청크 복원 오류: {e}")
            return None
    
    def get_capacity(self, file_path: str) -> int:
        """프레임 삽입 용량 계산"""
        try:
            cap = cv2.VideoCapture(file_path)
            if not cap.isOpened():
                return 0
            
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            cap.release()
            
            # 사용 가능한 삽입 슬롯 수
            max_injections = min(self.max_injections, total_frames // self.injection_interval)
            
            # 각 QR 코드당 용량 (헤더 제외)
            usable_chunk_size = self.chunk_size - 20  # 청크 헤더용 20바이트 예약
            
            # 총 용량 (바이트 단위)
            total_capacity = max_injections * usable_chunk_size
            
            return total_capacity
            
        except Exception as e:
            print(f"❌ 용량 계산 오류: {e}")
            return 0
    
    def analyze_suitability(self, file_path: str) -> Dict:
        """프레임 삽입 적합성 분석"""
        try:
            cap = cv2.VideoCapture(file_path)
            if not cap.isOpened():
                return {'suitability_score': 0.0, 'recommended': False}
            
            # 비디오 속성
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            duration = total_frames / fps if fps > 0 else 0
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            cap.release()
            
            # 적합성 점수 계산
            frame_count_score = min(total_frames / 300, 1.0)  # 300 프레임 이상이면 1.0
            fps_score = min(fps / 24.0, 1.0) if fps > 0 else 0  # 24fps 이상이면 1.0
            resolution_score = min((width * height) / (640 * 480), 1.0)
            duration_score = min(duration / 30.0, 1.0)  # 30초 이상이면 1.0
            
            # QR 코드 삽입 가능성 (해상도 기반)
            qr_fit_score = 1.0 if min(width, height) >= self.qr_size * 2 else 0.5
            
            suitability_score = (frame_count_score * 0.25 + 
                               fps_score * 0.2 + 
                               resolution_score * 0.2 +
                               duration_score * 0.2 +
                               qr_fit_score * 0.15)
            
            # 사용 가능한 삽입 슬롯
            available_slots = min(self.max_injections, total_frames // self.injection_interval)
            
            return {
                'suitability_score': suitability_score,
                'total_frames': total_frames,
                'fps': fps,
                'duration': duration,
                'resolution': f"{width}x{height}",
                'available_injection_slots': available_slots,
                'estimated_capacity': self.get_capacity(file_path),
                'recommended': (suitability_score > 0.7 and 
                              available_slots >= 10 and
                              min(width, height) >= self.qr_size * 2)
            }
            
        except Exception as e:
            print(f"❌ 적합성 분석 오류: {e}")
            return {'suitability_score': 0.0, 'recommended': False}
    
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
    print("📽️ Frame Injection 비디오 스테가노그래피 v3.0")
    print("=" * 55)
    
    # 인스턴스 생성
    frame_injector = FrameInjectionSteganography()
    
    # 예시 파일 경로
    input_video = "sample_video.mp4"
    output_video = "frame_injected_video.mp4"
    
    # 테스트 메시지
    test_message = "📽️ 프레임 삽입 테스트 - Frame Injection with QR Codes!"
    
    print(f"📝 테스트 메시지: {test_message}")
    
    # 실제 파일이 있을 경우의 테스트 코드
    # if Path(input_video).exists():
    #     analysis = frame_injector.analyze_suitability(input_video)
    #     print(f"📊 적합성 점수: {analysis['suitability_score']:.3f}")
    #     print(f"🎬 사용 가능한 삽입 슬롯: {analysis['available_injection_slots']}")
    #     
    #     if analysis['recommended']:
    #         success = frame_injector.embed_message(
    #             input_video, test_message, output_video, "frame_inject_123"
    #         )
    #         
    #         if success:
    #             extracted = frame_injector.extract_message(
    #                 output_video, "frame_inject_123"
    #             )
    #             print(f"🔍 추출된 메시지: {extracted}")
    
    print("\n💡 프레임 삽입 특징:")
    print("- 서브리미널 프레임을 이용한 은밀한 데이터 은닉")
    print("- QR 코드 기반 고밀도 데이터 저장")
    print("- 인간의 시각적 인지 한계 활용")
    print("- 원본 비디오 품질과 흐름 유지")