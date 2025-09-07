"""
무음 구간 조작(Silence Interval Manipulation) 오디오 스테가노그래피 v3.0

무음 구간 조작은 오디오의 무음 부분의 길이나 특성을 변경하여 데이터를 은닉하는 기법입니다.
음성이나 음악 파일에서 자연스럽게 발생하는 무음 구간을 활용하므로 은닉성이 뛰어납니다.

주요 특징:
- 무음 구간의 길이를 미세하게 조정하여 데이터 표현
- 청취자가 인지하기 어려운 미세한 변화 활용
- 음성 인식이나 압축에 상대적으로 강함
- 자연스러운 음성/음악 패턴 유지
"""

import numpy as np
import wave
import struct
from typing import Tuple, Dict, Optional, List
from pathlib import Path
from scipy import signal
from scipy.io import wavfile
import librosa
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import os

class SilenceManipulationSteganography:
    """무음 구간 조작 스테가노그래피 클래스"""
    
    def __init__(self):
        """초기화"""
        self.version = "3.0.0"
        self.author = "디지털포렌식 연구소"
        
        # 무음 감지 파라미터
        self.silence_threshold = 0.01  # 무음으로 간주할 임계값
        self.min_silence_duration = 0.1  # 최소 무음 구간 길이 (초)
        self.max_silence_extension = 0.05  # 최대 무음 연장 시간 (초)
        
        # 데이터 인코딩 파라미터
        self.base_unit = 0.01  # 기본 시간 단위 (초)
        self.bit_0_extension = 0.01  # 0 비트를 위한 연장 시간
        self.bit_1_extension = 0.02  # 1 비트를 위한 연장 시간
        
        # 프레임 분석 파라미터
        self.frame_size = 1024  # 프레임 크기
        self.hop_length = 512   # 홉 길이
        
        # 데이터 처리
        self.header_marker = b"SILENCE_MANIP_V3"
        self.encoding = 'utf-8'
        
        # 암호화 설정
        self.key_length = 32
        self.iv_length = 16
        self.salt_length = 16
        
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None) -> bool:
        """
        메시지를 무음 구간 조작으로 임베딩
        
        Args:
            input_path: 입력 오디오 파일 경로
            message: 숨길 메시지
            output_path: 출력 오디오 파일 경로
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 임베딩 성공 여부
        """
        try:
            # 오디오 파일 읽기
            audio_data, sample_rate = self._load_audio(input_path)
            original_params = self._get_wav_params(input_path)
            
            # 메시지 준비
            if password:
                encrypted_data = self._encrypt_message(message, password)
                binary_data = self._prepare_encrypted_data(encrypted_data)
            else:
                binary_data = self._prepare_plain_data(message)
            
            # 무음 구간 검출
            silence_intervals = self._detect_silence_intervals(audio_data, sample_rate)
            
            if len(silence_intervals) == 0:
                print("❌ 적절한 무음 구간을 찾을 수 없습니다")
                return False
            
            # 용량 확인
            capacity = len(silence_intervals)
            required_bits = len(binary_data)
            
            if required_bits > capacity:
                print(f"⚠️ 용량 부족: 필요 {required_bits} bits > 가용 {capacity} bits")
                return False
            
            # 무음 구간에 데이터 임베딩
            stego_audio = self._embed_data_in_silence(
                audio_data, silence_intervals, binary_data, sample_rate
            )
            
            # 스테고 오디오 파일 저장
            self._save_audio(output_path, stego_audio, sample_rate, original_params)
            
            print(f"✅ 무음 구간 조작 완료: {len(message)} 글자 → {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ 무음 구간 조작 임베딩 오류: {e}")
            return False
    
    def extract_message(self, input_path: str,
                       password: Optional[str] = None) -> Optional[str]:
        """
        무음 구간에서 메시지 추출
        
        Args:
            input_path: 스테고 오디오 파일 경로
            password: 복호화 패스워드 (선택사항)
            
        Returns:
            str: 추출된 메시지 또는 None
        """
        try:
            # 오디오 파일 읽기
            audio_data, sample_rate = self._load_audio(input_path)
            
            # 무음 구간 분석
            silence_intervals = self._detect_silence_intervals(audio_data, sample_rate)
            
            if len(silence_intervals) == 0:
                print("❌ 무음 구간을 찾을 수 없습니다")
                return None
            
            # 무음 구간에서 데이터 추출
            binary_data = self._extract_data_from_silence(
                audio_data, silence_intervals, sample_rate
            )
            
            if not binary_data:
                print("❌ 은닉된 데이터를 찾을 수 없습니다")
                return None
            
            # 메시지 복원
            if password:
                return self._restore_encrypted_message(binary_data, password)
            else:
                return self._restore_plain_message(binary_data)
                
        except Exception as e:
            print(f"❌ 무음 구간 추출 오류: {e}")
            return None
    
    def _detect_silence_intervals(self, audio_data: np.ndarray, 
                                 sample_rate: int) -> List[Tuple[int, int]]:
        """무음 구간 검출"""
        silence_intervals = []
        
        # 오디오 데이터가 스테레오인 경우 모노로 변환
        if len(audio_data.shape) > 1:
            audio_data = np.mean(audio_data, axis=1)
        
        # RMS 에너지 계산
        frame_length = int(self.frame_size)
        hop_length = int(self.hop_length)
        
        # 프레임별 RMS 계산
        rms_values = []
        for i in range(0, len(audio_data) - frame_length, hop_length):
            frame = audio_data[i:i + frame_length]
            rms = np.sqrt(np.mean(frame ** 2))
            rms_values.append(rms)
        
        rms_values = np.array(rms_values)
        
        # 무음 구간 식별
        silence_frames = rms_values < self.silence_threshold
        
        # 연속된 무음 프레임을 구간으로 그룹화
        in_silence = False
        silence_start = 0
        
        for i, is_silent in enumerate(silence_frames):
            if is_silent and not in_silence:
                # 무음 구간 시작
                silence_start = i
                in_silence = True
            elif not is_silent and in_silence:
                # 무음 구간 종료
                silence_end = i
                in_silence = False
                
                # 무음 구간 길이 확인
                silence_duration = (silence_end - silence_start) * hop_length / sample_rate
                if silence_duration >= self.min_silence_duration:
                    # 샘플 단위로 변환
                    start_sample = silence_start * hop_length
                    end_sample = silence_end * hop_length
                    silence_intervals.append((start_sample, end_sample))
        
        # 마지막 프레임이 무음인 경우 처리
        if in_silence:
            silence_end = len(silence_frames)
            silence_duration = (silence_end - silence_start) * hop_length / sample_rate
            if silence_duration >= self.min_silence_duration:
                start_sample = silence_start * hop_length
                end_sample = min(silence_end * hop_length, len(audio_data))
                silence_intervals.append((start_sample, end_sample))
        
        return silence_intervals
    
    def _embed_data_in_silence(self, audio_data: np.ndarray,
                              silence_intervals: List[Tuple[int, int]],
                              binary_data: str, sample_rate: int) -> np.ndarray:
        """무음 구간에 데이터 임베딩"""
        stego_audio = audio_data.copy()
        
        # 스테레오 처리
        is_stereo = len(audio_data.shape) > 1
        if is_stereo:
            channels = audio_data.shape[1]
        else:
            channels = 1
            stego_audio = stego_audio.reshape(-1, 1)
        
        # 각 무음 구간에 비트 임베딩
        for i, bit_char in enumerate(binary_data):
            if i >= len(silence_intervals):
                break
                
            start, end = silence_intervals[i]
            bit = int(bit_char)
            
            # 비트 값에 따른 무음 구간 연장
            if bit == 1:
                extension_samples = int(self.bit_1_extension * sample_rate)
            else:
                extension_samples = int(self.bit_0_extension * sample_rate)
            
            # 무음 구간 연장 (0으로 패딩)
            if extension_samples > 0:
                # 무음 구간 뒤에 0값 추가
                if is_stereo:
                    silence_extension = np.zeros((extension_samples, channels))
                else:
                    silence_extension = np.zeros((extension_samples, 1))
                
                # 오디오 배열 재구성
                before_silence = stego_audio[:end]
                after_silence = stego_audio[end:]
                
                stego_audio = np.vstack([before_silence, silence_extension, after_silence])
                
                # 후속 무음 구간 인덱스 업데이트
                for j in range(i + 1, len(silence_intervals)):
                    old_start, old_end = silence_intervals[j]
                    silence_intervals[j] = (old_start + extension_samples, 
                                           old_end + extension_samples)
        
        # 스테레오가 아닌 경우 1차원으로 변환
        if not is_stereo:
            stego_audio = stego_audio.flatten()
        
        return stego_audio
    
    def _extract_data_from_silence(self, audio_data: np.ndarray,
                                  silence_intervals: List[Tuple[int, int]],
                                  sample_rate: int) -> Optional[str]:
        """무음 구간에서 데이터 추출"""
        extracted_bits = []
        
        # 각 무음 구간의 길이 분석
        for start, end in silence_intervals:
            silence_duration = (end - start) / sample_rate
            
            # 기준 시간과 비교하여 비트 결정
            # 기준보다 긴 무음 구간은 1, 짧은 구간은 0으로 간주
            if silence_duration > (self.min_silence_duration + self.bit_0_extension + 
                                  self.bit_1_extension) / 2:
                extracted_bits.append('1')
            else:
                extracted_bits.append('0')
        
        binary_data = ''.join(extracted_bits)
        
        # 헤더 검증
        if not self._validate_header(binary_data):
            return None
        
        return binary_data
    
    def get_capacity(self, file_path: str) -> int:
        """무음 구간 조작 용량 계산"""
        try:
            audio_data, sample_rate = self._load_audio(file_path)
            silence_intervals = self._detect_silence_intervals(audio_data, sample_rate)
            
            # 사용 가능한 무음 구간 수가 곧 용량
            capacity = len(silence_intervals)
            
            # 헤더와 메타데이터를 위한 여유 확보
            usable_capacity = max(0, capacity - 200)  # 헤더용 200비트 예약
            
            return usable_capacity
            
        except Exception as e:
            print(f"❌ 용량 계산 오류: {e}")
            return 0
    
    def analyze_suitability(self, file_path: str) -> Dict:
        """무음 구간 조작 적합성 분석"""
        try:
            audio_data, sample_rate = self._load_audio(file_path)
            duration = len(audio_data) / sample_rate
            
            # 무음 구간 분석
            silence_intervals = self._detect_silence_intervals(audio_data, sample_rate)
            total_silence_duration = sum([(end - start) / sample_rate 
                                        for start, end in silence_intervals])
            
            # 적합성 점수 계산
            silence_ratio = total_silence_duration / duration if duration > 0 else 0
            interval_count_score = min(len(silence_intervals) / 100, 1.0)
            duration_score = min(duration / 30.0, 1.0)  # 30초 이상이면 1.0
            
            # 무음 구간의 분포 균등성 분석
            if len(silence_intervals) > 1:
                intervals_distribution = np.std([end - start for start, end in silence_intervals])
                distribution_score = 1.0 / (1.0 + intervals_distribution / 1000)
            else:
                distribution_score = 0.0
            
            suitability_score = (silence_ratio * 0.3 + 
                               interval_count_score * 0.3 +
                               duration_score * 0.2 + 
                               distribution_score * 0.2)
            
            return {
                'suitability_score': suitability_score,
                'silence_intervals_count': len(silence_intervals),
                'total_silence_duration': total_silence_duration,
                'silence_ratio': silence_ratio,
                'audio_duration': duration,
                'estimated_capacity': self.get_capacity(file_path),
                'recommended': suitability_score > 0.5 and len(silence_intervals) > 50
            }
            
        except Exception as e:
            print(f"❌ 적합성 분석 오류: {e}")
            return {'suitability_score': 0.0, 'recommended': False}
    
    def _load_audio(self, file_path: str) -> Tuple[np.ndarray, int]:
        """오디오 파일 로드"""
        try:
            # librosa를 사용하여 오디오 로드 (다양한 포맷 지원)
            audio_data, sample_rate = librosa.load(file_path, sr=None, mono=False)
            
            # 스테레오인 경우 채널 축 조정
            if audio_data.ndim > 1:
                audio_data = audio_data.T
            
            return audio_data, sample_rate
        except:
            # librosa 실패 시 wave 모듈 사용
            with wave.open(file_path, 'rb') as wav_file:
                frames = wav_file.getnframes()
                sample_rate = wav_file.getframerate()
                sample_width = wav_file.getsampwidth()
                channels = wav_file.getnchannels()
                
                raw_audio = wav_file.readframes(frames)
                
                if sample_width == 1:
                    audio_data = np.frombuffer(raw_audio, dtype=np.uint8)
                    audio_data = audio_data.astype(np.float32) / 128.0 - 1.0
                elif sample_width == 2:
                    audio_data = np.frombuffer(raw_audio, dtype=np.int16)
                    audio_data = audio_data.astype(np.float32) / 32768.0
                else:
                    audio_data = np.frombuffer(raw_audio, dtype=np.int32)
                    audio_data = audio_data.astype(np.float32) / 2147483648.0
                
                if channels == 2:
                    audio_data = audio_data.reshape(-1, 2)
                
                return audio_data, sample_rate
    
    def _get_wav_params(self, file_path: str) -> Dict:
        """WAV 파일 파라미터 추출"""
        try:
            with wave.open(file_path, 'rb') as wav_file:
                return {
                    'nchannels': wav_file.getnchannels(),
                    'sampwidth': wav_file.getsampwidth(),
                    'framerate': wav_file.getframerate(),
                    'nframes': wav_file.getnframes()
                }
        except:
            return {
                'nchannels': 1,
                'sampwidth': 2,
                'framerate': 44100,
                'nframes': 0
            }
    
    def _save_audio(self, file_path: str, audio_data: np.ndarray,
                   sample_rate: int, original_params: Dict) -> None:
        """오디오 파일 저장"""
        try:
            # numpy 배열을 적절한 데이터 타입으로 변환
            if original_params['sampwidth'] == 1:
                audio_int = ((audio_data + 1.0) * 128.0).astype(np.uint8)
            elif original_params['sampwidth'] == 2:
                audio_int = (audio_data * 32767.0).astype(np.int16)
            else:
                audio_int = (audio_data * 2147483647.0).astype(np.int32)
            
            # WAV 파일로 저장
            with wave.open(file_path, 'wb') as wav_file:
                wav_file.setnchannels(original_params['nchannels'])
                wav_file.setsampwidth(original_params['sampwidth'])
                wav_file.setframerate(sample_rate)
                
                # 스테레오인 경우 인터리브
                if len(audio_int.shape) > 1:
                    audio_int = audio_int.flatten()
                
                wav_file.writeframes(audio_int.tobytes())
        except Exception as e:
            print(f"⚠️ WAV 저장 실패, 다른 방법 시도: {e}")
            # scipy를 사용한 대안 저장
            try:
                wavfile.write(file_path, sample_rate, audio_data)
            except Exception as e2:
                raise Exception(f"오디오 저장 실패: {e2}")
    
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
    print("🤫 Silence Manipulation 오디오 스테가노그래피 v3.0")
    print("=" * 55)
    
    # 인스턴스 생성
    silence_manipulator = SilenceManipulationSteganography()
    
    # 예시 파일 경로
    input_audio = "sample_speech.wav"
    output_audio = "silence_manipulated_audio.wav"
    
    # 테스트 메시지
    test_message = "🤫 무음 구간 조작 테스트 - Silence Manipulation Steganography!"
    
    print(f"📝 테스트 메시지: {test_message}")
    
    # 실제 파일이 있을 경우의 테스트 코드 (주석 처리)
    # if Path(input_audio).exists():
    #     analysis = silence_manipulator.analyze_suitability(input_audio)
    #     print(f"📊 적합성 점수: {analysis['suitability_score']:.3f}")
    #     print(f"🔇 무음 구간 수: {analysis['silence_intervals_count']}")
    #     
    #     if analysis['recommended']:
    #         success = silence_manipulator.embed_message(
    #             input_audio, test_message, output_audio, "silence123"
    #         )
    #         
    #         if success:
    #             extracted = silence_manipulator.extract_message(
    #                 output_audio, "silence123"
    #             )
    #             print(f"🔍 추출된 메시지: {extracted}")
    
    print("\n💡 무음 구간 조작 특징:")
    print("- 자연스러운 무음 구간의 미세한 길이 변조")
    print("- 음성이나 대화 내용이 포함된 오디오에 최적화")
    print("- 압축과 변환에 상대적으로 강한 저항성")
    print("- 청취자가 인지하기 어려운 미세한 변화 활용")