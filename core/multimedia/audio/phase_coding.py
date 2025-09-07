"""
위상 코딩(Phase Coding) 오디오 스테가노그래피 v3.0

위상 코딩은 오디오 신호의 위상(phase) 정보를 조작하여 데이터를 은닉하는 고급 기법입니다.
인간의 청각 시스템은 위상 변화에 상대적으로 둔감하기 때문에 높은 음질을 유지하면서 데이터 은닉이 가능합니다.

주요 특징:
- FFT/IFFT를 사용한 주파수 도메인 처리
- 위상 스펙트럼 조작을 통한 데이터 임베딩
- 높은 은닉성과 좋은 음질 보존
- 압축에 어느 정도 저항성
"""

import numpy as np
import wave
import struct
from typing import Tuple, Dict, Optional, List
from pathlib import Path
from scipy.fft import fft, ifft, fftfreq
from scipy.signal import spectrogram
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import os
import warnings

class PhaseCodingSteganography:
    """위상 코딩 스테가노그래피 클래스"""
    
    def __init__(self):
        """초기화"""
        self.version = "3.0.0"
        self.author = "디지털포렌식 연구소"
        
        # 위상 코딩 파라미터
        self.segment_length = 8192  # FFT 세그먼트 길이 (2^13)
        self.overlap = 4096  # 세그먼트 간 오버랩
        self.phase_delta = np.pi / 4  # 위상 변화량 (45도)
        self.frequency_range = (1000, 8000)  # 사용할 주파수 범위 (Hz)
        
        # 데이터 처리 파라미터
        self.header_marker = b"PHASE_CODEC_V3"
        self.encoding = 'utf-8'
        
        # 암호화 설정
        self.key_length = 32  # AES-256
        self.iv_length = 16
        self.salt_length = 16
        
    def embed_message(self, input_path: str, message: str, output_path: str, 
                     password: Optional[str] = None) -> bool:
        """
        메시지를 오디오 파일에 위상 코딩으로 임베딩
        
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
            audio_data, audio_params = self._read_wav_file(input_path)
            
            # 스테레오를 모노로 변환 (필요한 경우)
            if len(audio_data.shape) > 1:
                audio_data = np.mean(audio_data, axis=1)
            
            # 메시지 준비
            if password:
                encrypted_data = self._encrypt_message(message, password)
                binary_data = self._prepare_encrypted_data(encrypted_data)
            else:
                binary_data = self._prepare_plain_data(message)
            
            # 용량 확인
            capacity = self.get_capacity(input_path)
            required_bits = len(binary_data)
            
            if required_bits > capacity:
                print(f"⚠️ 용량 부족: 필요 {required_bits} bits > 가용 {capacity} bits")
                return False
            
            # 위상 코딩으로 데이터 임베딩
            stego_audio = self._embed_data_phase_coding(audio_data, binary_data, 
                                                       audio_params['framerate'])
            
            # 스테고 오디오 파일 저장
            self._write_wav_file(output_path, stego_audio, audio_params)
            
            print(f"✅ 위상 코딩 임베딩 완료: {len(message)} 글자 → {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ 위상 코딩 임베딩 오류: {e}")
            return False
    
    def extract_message(self, input_path: str, 
                       password: Optional[str] = None) -> Optional[str]:
        """
        위상 코딩된 메시지를 추출
        
        Args:
            input_path: 스테고 오디오 파일 경로
            password: 복호화 패스워드 (선택사항)
            
        Returns:
            str: 추출된 메시지 또는 None
        """
        try:
            # 오디오 파일 읽기
            audio_data, audio_params = self._read_wav_file(input_path)
            
            # 스테레오를 모노로 변환 (필요한 경우)
            if len(audio_data.shape) > 1:
                audio_data = np.mean(audio_data, axis=1)
            
            # 위상 분석을 통한 데이터 추출
            binary_data = self._extract_data_phase_coding(audio_data, 
                                                         audio_params['framerate'])
            
            if not binary_data:
                print("❌ 위상 코딩된 데이터를 찾을 수 없습니다")
                return None
            
            # 메시지 복원
            if password:
                return self._restore_encrypted_message(binary_data, password)
            else:
                return self._restore_plain_message(binary_data)
                
        except Exception as e:
            print(f"❌ 위상 코딩 추출 오류: {e}")
            return None
    
    def _embed_data_phase_coding(self, audio_data: np.ndarray, binary_data: str,
                                sample_rate: int) -> np.ndarray:
        """위상 코딩을 사용한 데이터 임베딩"""
        stego_audio = audio_data.copy().astype(np.float64)
        data_index = 0
        
        # 세그먼트별로 처리
        for start in range(0, len(audio_data) - self.segment_length, 
                          self.segment_length - self.overlap):
            if data_index >= len(binary_data):
                break
                
            end = start + self.segment_length
            segment = stego_audio[start:end]
            
            # FFT 적용
            fft_data = fft(segment)
            magnitude = np.abs(fft_data)
            phase = np.angle(fft_data)
            
            # 주파수 범위 결정
            freqs = fftfreq(len(segment), 1/sample_rate)
            freq_mask = (freqs >= self.frequency_range[0]) & \
                       (freqs <= self.frequency_range[1])
            
            # 사용 가능한 주파수 빈 찾기
            usable_bins = np.where(freq_mask)[0]
            
            # 데이터 임베딩
            for bin_idx in usable_bins:
                if data_index >= len(binary_data):
                    break
                
                # 현재 비트 가져오기
                bit = int(binary_data[data_index])
                data_index += 1
                
                # 위상 조작
                if bit == 1:
                    # 1 비트: 위상 증가
                    phase[bin_idx] += self.phase_delta
                else:
                    # 0 비트: 위상 감소
                    phase[bin_idx] -= self.phase_delta
                
                # 위상을 [-π, π] 범위로 정규화
                phase[bin_idx] = self._normalize_phase(phase[bin_idx])
            
            # 수정된 위상으로 IFFT
            fft_data_modified = magnitude * np.exp(1j * phase)
            segment_modified = np.real(ifft(fft_data_modified))
            
            # 윈도잉 적용 (부드러운 연결을 위해)
            if start > 0:
                # 오버랩 영역에 윈도우 적용
                overlap_window = np.linspace(0, 1, self.overlap)
                segment_modified[:self.overlap] *= overlap_window
                stego_audio[start:start+self.overlap] *= (1 - overlap_window)
                stego_audio[start:start+self.overlap] += segment_modified[:self.overlap]
                stego_audio[start+self.overlap:end] = segment_modified[self.overlap:]
            else:
                stego_audio[start:end] = segment_modified
        
        # 진폭 정규화
        stego_audio = self._normalize_audio(stego_audio, audio_data.dtype)
        
        return stego_audio
    
    def _extract_data_phase_coding(self, audio_data: np.ndarray, 
                                  sample_rate: int) -> Optional[str]:
        """위상 코딩된 데이터 추출"""
        extracted_bits = []
        
        # 세그먼트별로 처리
        for start in range(0, len(audio_data) - self.segment_length,
                          self.segment_length - self.overlap):
            end = start + self.segment_length
            segment = audio_data[start:end]
            
            # FFT 적용
            fft_data = fft(segment)
            phase = np.angle(fft_data)
            
            # 주파수 범위 결정
            freqs = fftfreq(len(segment), 1/sample_rate)
            freq_mask = (freqs >= self.frequency_range[0]) & \
                       (freqs <= self.frequency_range[1])
            
            # 사용 가능한 주파수 빈 찾기
            usable_bins = np.where(freq_mask)[0]
            
            # 각 주파수 빈에서 데이터 추출
            for bin_idx in usable_bins:
                # 위상 변화 분석
                phase_value = phase[bin_idx]
                
                # 기준 위상과 비교하여 비트 결정
                # 단순화된 방법: 위상의 상위 비트 사용
                if np.sin(phase_value) > 0:
                    extracted_bits.append('1')
                else:
                    extracted_bits.append('0')
        
        # 추출된 비트를 문자열로 변환
        binary_data = ''.join(extracted_bits)
        
        # 헤더 검증
        if not self._validate_header(binary_data):
            return None
        
        return binary_data
    
    def _normalize_phase(self, phase: float) -> float:
        """위상을 [-π, π] 범위로 정규화"""
        while phase > np.pi:
            phase -= 2 * np.pi
        while phase < -np.pi:
            phase += 2 * np.pi
        return phase
    
    def _normalize_audio(self, audio_data: np.ndarray, original_dtype) -> np.ndarray:
        """오디오 진폭 정규화"""
        # 최대값으로 정규화
        max_val = np.max(np.abs(audio_data))
        if max_val > 0:
            audio_data = audio_data / max_val
        
        # 원래 데이터 타입에 맞게 스케일링
        if original_dtype == np.int16:
            return (audio_data * 32767).astype(np.int16)
        elif original_dtype == np.int32:
            return (audio_data * 2147483647).astype(np.int32)
        else:
            return audio_data.astype(original_dtype)
    
    def get_capacity(self, file_path: str) -> int:
        """위상 코딩 용량 계산"""
        try:
            audio_data, audio_params = self._read_wav_file(file_path)
            
            if len(audio_data.shape) > 1:
                audio_data = np.mean(audio_data, axis=1)
            
            sample_rate = audio_params['framerate']
            total_segments = (len(audio_data) - self.segment_length) // \
                           (self.segment_length - self.overlap) + 1
            
            # 각 세그먼트에서 사용 가능한 주파수 빈 수 계산
            freqs = fftfreq(self.segment_length, 1/sample_rate)
            freq_mask = (freqs >= self.frequency_range[0]) & \
                       (freqs <= self.frequency_range[1])
            usable_bins = np.sum(freq_mask)
            
            # 총 용량 (비트 단위)
            total_capacity = total_segments * usable_bins
            
            # 헤더와 메타데이터를 위한 여유 공간 확보 (20%)
            usable_capacity = int(total_capacity * 0.8)
            
            return usable_capacity
            
        except Exception as e:
            print(f"❌ 용량 계산 오류: {e}")
            return 0
    
    def analyze_suitability(self, file_path: str) -> Dict:
        """위상 코딩 적합성 분석"""
        try:
            audio_data, audio_params = self._read_wav_file(file_path)
            
            if len(audio_data.shape) > 1:
                audio_data = np.mean(audio_data, axis=1)
            
            sample_rate = audio_params['framerate']
            duration = len(audio_data) / sample_rate
            
            # 스펙트로그램 분석
            f, t, Sxx = spectrogram(audio_data, sample_rate, 
                                   nperseg=self.segment_length//4)
            
            # 주파수 범위 내 에너지 분석
            freq_mask = (f >= self.frequency_range[0]) & (f <= self.frequency_range[1])
            target_energy = np.mean(Sxx[freq_mask, :])
            total_energy = np.mean(Sxx)
            
            # 적합성 점수 계산
            energy_ratio = target_energy / total_energy if total_energy > 0 else 0
            duration_score = min(duration / 10.0, 1.0)  # 10초 이상이면 1.0
            frequency_coverage = np.sum(freq_mask) / len(f)
            
            suitability_score = (energy_ratio * 0.4 + duration_score * 0.3 + 
                               frequency_coverage * 0.3)
            
            return {
                'suitability_score': suitability_score,
                'duration': duration,
                'sample_rate': sample_rate,
                'target_frequency_energy': target_energy,
                'total_energy': total_energy,
                'frequency_coverage': frequency_coverage,
                'estimated_capacity': self.get_capacity(file_path),
                'recommended': suitability_score > 0.6
            }
            
        except Exception as e:
            print(f"❌ 적합성 분석 오류: {e}")
            return {'suitability_score': 0.0, 'recommended': False}
    
    def _read_wav_file(self, file_path: str) -> Tuple[np.ndarray, dict]:
        """WAV 파일 읽기"""
        with wave.open(file_path, 'rb') as wav_file:
            frames = wav_file.getnframes()
            sample_rate = wav_file.getframerate()
            sample_width = wav_file.getsampwidth()
            channels = wav_file.getnchannels()
            
            # 오디오 데이터 읽기
            raw_audio = wav_file.readframes(frames)
            
            # 데이터 타입 결정
            if sample_width == 1:
                dtype = np.uint8
                audio_data = np.frombuffer(raw_audio, dtype=dtype)
            elif sample_width == 2:
                dtype = np.int16
                audio_data = np.frombuffer(raw_audio, dtype=dtype)
            elif sample_width == 4:
                dtype = np.int32
                audio_data = np.frombuffer(raw_audio, dtype=dtype)
            else:
                raise ValueError(f"지원되지 않는 샘플 너비: {sample_width}")
            
            # 스테레오인 경우 채널별로 분리
            if channels == 2:
                audio_data = audio_data.reshape(-1, 2)
            
            params = {
                'framerate': sample_rate,
                'sampwidth': sample_width,
                'nchannels': channels,
                'nframes': frames
            }
            
            return audio_data, params
    
    def _write_wav_file(self, file_path: str, audio_data: np.ndarray, 
                       params: dict) -> None:
        """WAV 파일 쓰기"""
        with wave.open(file_path, 'wb') as wav_file:
            wav_file.setnchannels(params['nchannels'])
            wav_file.setsampwidth(params['sampwidth'])
            wav_file.setframerate(params['framerate'])
            
            # 스테레오인 경우 인터리브
            if params['nchannels'] == 2 and len(audio_data.shape) == 2:
                audio_data = audio_data.flatten()
            
            wav_file.writeframes(audio_data.tobytes())
    
    def _prepare_plain_data(self, message: str) -> str:
        """평문 데이터 준비"""
        # 메시지를 바이트로 변환
        message_bytes = message.encode(self.encoding)
        
        # 헤더 + 길이 + 메시지
        length_bytes = len(message_bytes).to_bytes(4, byteorder='big')
        full_data = self.header_marker + length_bytes + message_bytes
        
        # 바이트를 비트 문자열로 변환
        binary_data = ''.join(format(byte, '08b') for byte in full_data)
        
        return binary_data
    
    def _prepare_encrypted_data(self, encrypted_data: bytes) -> str:
        """암호화된 데이터 준비"""
        # 헤더 + 길이 + 암호화된 데이터
        length_bytes = len(encrypted_data).to_bytes(4, byteorder='big')
        full_data = self.header_marker + b"_ENC" + length_bytes + encrypted_data
        
        # 바이트를 비트 문자열로 변환
        binary_data = ''.join(format(byte, '08b') for byte in full_data)
        
        return binary_data
    
    def _validate_header(self, binary_data: str) -> bool:
        """헤더 유효성 검증"""
        if len(binary_data) < len(self.header_marker) * 8:
            return False
        
        # 헤더 부분 추출
        header_bits = binary_data[:len(self.header_marker) * 8]
        header_bytes = bytes([int(header_bits[i:i+8], 2) 
                             for i in range(0, len(header_bits), 8)])
        
        return header_bytes == self.header_marker
    
    def _restore_plain_message(self, binary_data: str) -> str:
        """평문 메시지 복원"""
        try:
            # 헤더 건너뛰기
            offset = len(self.header_marker) * 8
            
            # 메시지 길이 추출
            length_bits = binary_data[offset:offset + 32]
            message_length = int(length_bits, 2)
            offset += 32
            
            # 메시지 데이터 추출
            message_bits = binary_data[offset:offset + message_length * 8]
            
            if len(message_bits) < message_length * 8:
                raise ValueError("데이터가 불완전합니다")
            
            # 비트를 바이트로 변환
            message_bytes = bytes([int(message_bits[i:i+8], 2) 
                                  for i in range(0, len(message_bits), 8)])
            
            return message_bytes.decode(self.encoding)
            
        except Exception as e:
            print(f"❌ 평문 메시지 복원 오류: {e}")
            return None
    
    def _restore_encrypted_message(self, binary_data: str, password: str) -> str:
        """암호화된 메시지 복원"""
        try:
            # 헤더 + "_ENC" 건너뛰기
            offset = (len(self.header_marker) + 4) * 8
            
            # 암호화된 데이터 길이 추출
            length_bits = binary_data[offset:offset + 32]
            data_length = int(length_bits, 2)
            offset += 32
            
            # 암호화된 데이터 추출
            data_bits = binary_data[offset:offset + data_length * 8]
            
            if len(data_bits) < data_length * 8:
                raise ValueError("암호화된 데이터가 불완전합니다")
            
            # 비트를 바이트로 변환
            encrypted_data = bytes([int(data_bits[i:i+8], 2) 
                                   for i in range(0, len(data_bits), 8)])
            
            # 복호화
            return self._decrypt_message(encrypted_data, password)
            
        except Exception as e:
            print(f"❌ 암호화된 메시지 복원 오류: {e}")
            return None
    
    def _encrypt_message(self, message: str, password: str) -> bytes:
        """메시지 암호화 (AES-256-GCM)"""
        try:
            # 솔트 생성
            salt = os.urandom(self.salt_length)
            
            # PBKDF2로 키 유도
            key = PBKDF2(password, salt, dkLen=self.key_length)
            
            # AES-GCM 암호화
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(message.encode(self.encoding))
            
            # 솔트 + nonce + tag + ciphertext 결합
            encrypted_data = salt + cipher.nonce + tag + ciphertext
            
            return encrypted_data
            
        except Exception as e:
            raise Exception(f"암호화 실패: {e}")
    
    def _decrypt_message(self, encrypted_data: bytes, password: str) -> str:
        """메시지 복호화 (AES-256-GCM)"""
        try:
            # 구성 요소 분리
            salt = encrypted_data[:self.salt_length]
            nonce = encrypted_data[self.salt_length:self.salt_length + 16]
            tag = encrypted_data[self.salt_length + 16:self.salt_length + 32]
            ciphertext = encrypted_data[self.salt_length + 32:]
            
            # PBKDF2로 키 유도
            key = PBKDF2(password, salt, dkLen=self.key_length)
            
            # AES-GCM 복호화
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode(self.encoding)
            
        except Exception as e:
            raise Exception(f"복호화 실패: {e}")

# 사용 예시 및 테스트
if __name__ == "__main__":
    print("🎵 Phase Coding 오디오 스테가노그래피 v3.0")
    print("=" * 50)
    
    # 인스턴스 생성
    phase_coder = PhaseCodingSteganography()
    
    # 예시 파일 경로 (실제 사용 시 수정 필요)
    input_audio = "sample_audio.wav"
    output_audio = "phase_coded_audio.wav"
    
    # 테스트 메시지
    test_message = "🎵 위상 코딩 테스트 메시지 - Phase Coding Steganography Test!"
    
    print(f"📝 테스트 메시지: {test_message}")
    
    # 파일 존재 확인 (실제 구현에서만)
    # if Path(input_audio).exists():
    #     # 적합성 분석
    #     analysis = phase_coder.analyze_suitability(input_audio)
    #     print(f"📊 적합성 점수: {analysis['suitability_score']:.3f}")
    #     print(f"💾 예상 용량: {analysis['estimated_capacity']} bits")
    #     
    #     # 메시지 임베딩
    #     success = phase_coder.embed_message(input_audio, test_message, 
    #                                        output_audio, "phase_test_123")
    #     
    #     if success:
    #         # 메시지 추출
    #         extracted = phase_coder.extract_message(output_audio, "phase_test_123")
    #         print(f"🔍 추출된 메시지: {extracted}")
    #         
    #         if extracted == test_message:
    #             print("✅ 위상 코딩 테스트 성공!")
    #         else:
    #             print("❌ 위상 코딩 테스트 실패")
    
    print("\n💡 위상 코딩 특징:")
    print("- 주파수 도메인에서 위상 조작을 통한 데이터 은닉")
    print("- 인간의 청각적 인지 한계를 활용한 높은 은닉성")
    print("- FFT/IFFT 기반 정교한 신호 처리")
    print("- 음악, 음성 등 다양한 오디오에 적용 가능")