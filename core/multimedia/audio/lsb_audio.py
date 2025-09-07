"""
LSB 오디오 스테가노그래피 알고리즘

오디오 샘플의 최하위 비트(LSB)를 조작하여 데이터를 은닉하는 기법입니다.
인간의 청각 시스템이 미세한 진폭 변화에 덜 민감하다는 특성을 이용합니다.

Reference: Bender et al. (1996), "Techniques for data hiding"
"""

import numpy as np
import wave
import struct
import logging
from typing import Optional, Tuple
from ...utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class LSBAudioSteganography:
    """LSB 오디오 스테가노그래피 구현"""
    
    def __init__(self, sample_rate: int = 44100, channels: int = 1, sample_width: int = 2):
        """
        Args:
            sample_rate: 샘플링 주파수 (Hz)
            channels: 채널 수 (1=모노, 2=스테레오)
            sample_width: 샘플 너비 (바이트 단위, 1=8bit, 2=16bit, 4=32bit)
        """
        self.sample_rate = sample_rate
        self.channels = channels
        self.sample_width = sample_width
        self.max_amplitude = (2 ** (sample_width * 8 - 1)) - 1
    
    def _read_wav_file(self, file_path: str) -> Tuple[np.ndarray, dict]:
        """WAV 파일 읽기"""
        try:
            with wave.open(file_path, 'rb') as wav_file:
                # 파일 정보 읽기
                frames = wav_file.getnframes()
                sample_rate = wav_file.getframerate()
                channels = wav_file.getnchannels()
                sample_width = wav_file.getsampwidth()
                
                # 오디오 데이터 읽기
                audio_data = wav_file.readframes(frames)
                
                # numpy 배열로 변환
                if sample_width == 1:  # 8-bit
                    audio_array = np.frombuffer(audio_data, dtype=np.uint8)
                    audio_array = audio_array.astype(np.int16) - 128  # 부호 있는 정수로 변환
                elif sample_width == 2:  # 16-bit
                    audio_array = np.frombuffer(audio_data, dtype=np.int16)
                elif sample_width == 4:  # 32-bit
                    audio_array = np.frombuffer(audio_data, dtype=np.int32)
                else:
                    raise ValueError(f"지원하지 않는 샘플 너비: {sample_width}")
                
                # 스테레오인 경우 채널별 분리
                if channels == 2:
                    audio_array = audio_array.reshape(-1, 2)
                
                file_info = {
                    'sample_rate': sample_rate,
                    'channels': channels,
                    'sample_width': sample_width,
                    'frames': frames,
                    'duration': frames / sample_rate
                }
                
                return audio_array, file_info
                
        except Exception as e:
            logger.error(f"WAV 파일 읽기 실패 {file_path}: {e}")
            return None, None
    
    def _write_wav_file(self, file_path: str, audio_array: np.ndarray, 
                       file_info: dict) -> bool:
        """WAV 파일 쓰기"""
        try:
            with wave.open(file_path, 'wb') as wav_file:
                wav_file.setnchannels(file_info['channels'])
                wav_file.setsampwidth(file_info['sample_width'])
                wav_file.setframerate(file_info['sample_rate'])
                
                # numpy 배열을 바이트로 변환
                if file_info['sample_width'] == 1:  # 8-bit
                    audio_data = (audio_array + 128).astype(np.uint8).tobytes()
                elif file_info['sample_width'] == 2:  # 16-bit
                    audio_data = audio_array.astype(np.int16).tobytes()
                elif file_info['sample_width'] == 4:  # 32-bit
                    audio_data = audio_array.astype(np.int32).tobytes()
                
                wav_file.writeframes(audio_data)
            
            return True
            
        except Exception as e:
            logger.error(f"WAV 파일 쓰기 실패 {file_path}: {e}")
            return False
    
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None, channel: int = 0) -> bool:
        """LSB 방법으로 오디오에 메시지 임베딩"""
        try:
            # 오디오 파일 읽기
            audio_array, file_info = self._read_wav_file(input_path)
            if audio_array is None:
                return False
            
            logger.info(f"오디오 정보: {file_info['duration']:.2f}초, "
                       f"{file_info['sample_rate']}Hz, "
                       f"{file_info['channels']}채널")
            
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
            
            # 용량 체크
            if file_info['channels'] == 1:
                available_samples = len(audio_array)
            else:
                available_samples = len(audio_array) * file_info['channels']
            
            if len(total_bits) > available_samples:
                logger.error(f"메시지가 너무 큽니다. 최대 {available_samples}비트, 요청 {len(total_bits)}비트")
                return False
            
            # LSB 임베딩
            stego_audio = audio_array.copy()
            bit_index = 0
            
            if file_info['channels'] == 1:  # 모노
                for i in range(len(audio_array)):
                    if bit_index >= len(total_bits):
                        break
                    
                    # 현재 샘플의 LSB를 메시지 비트로 교체
                    sample = int(stego_audio[i])
                    bit = int(total_bits[bit_index])
                    
                    # LSB 설정
                    new_sample = (sample & ~1) | bit
                    stego_audio[i] = new_sample
                    
                    bit_index += 1
            
            else:  # 스테레오
                for i in range(len(audio_array)):
                    for ch in range(file_info['channels']):
                        if bit_index >= len(total_bits):
                            break
                        
                        # 지정된 채널 또는 모든 채널 사용
                        if channel == -1 or ch == channel:
                            sample = int(stego_audio[i, ch])
                            bit = int(total_bits[bit_index])
                            
                            new_sample = (sample & ~1) | bit
                            stego_audio[i, ch] = new_sample
                            
                            bit_index += 1
                    
                    if bit_index >= len(total_bits):
                        break
            
            # 결과 파일 저장
            success = self._write_wav_file(output_path, stego_audio, file_info)
            
            if success:
                logger.info(f"LSB 오디오 임베딩 완료: {output_path}")
            
            return success
            
        except Exception as e:
            logger.error(f"LSB 오디오 임베딩 실패: {e}")
            return False
    
    def extract_message(self, input_path: str, password: Optional[str] = None,
                       channel: int = 0) -> Optional[str]:
        """LSB 방법으로 오디오에서 메시지 추출"""
        try:
            # 오디오 파일 읽기
            audio_array, file_info = self._read_wav_file(input_path)
            if audio_array is None:
                return None
            
            # 메시지 길이 추출 (처음 32비트)
            extracted_bits = ""
            bit_count = 0
            
            if file_info['channels'] == 1:  # 모노
                for i in range(len(audio_array)):
                    if bit_count >= 32:
                        break
                    
                    sample = int(audio_array[i])
                    bit = sample & 1
                    extracted_bits += str(bit)
                    bit_count += 1
            
            else:  # 스테레오
                for i in range(len(audio_array)):
                    for ch in range(file_info['channels']):
                        if bit_count >= 32:
                            break
                        
                        if channel == -1 or ch == channel:
                            sample = int(audio_array[i, ch])
                            bit = sample & 1
                            extracted_bits += str(bit)
                            bit_count += 1
                    
                    if bit_count >= 32:
                        break
            
            if len(extracted_bits) < 32:
                logger.error("메시지 길이 정보를 읽을 수 없습니다")
                return None
            
            message_length = int(extracted_bits[:32], 2)
            logger.info(f"메시지 길이: {message_length} 비트")
            
            if message_length <= 0 or message_length > 1000000:  # 1MB 제한
                logger.error("유효하지 않은 메시지 길이")
                return None
            
            # 전체 메시지 추출
            total_bits_needed = 32 + message_length
            extracted_bits = ""
            bit_count = 0
            
            if file_info['channels'] == 1:  # 모노
                for i in range(len(audio_array)):
                    if bit_count >= total_bits_needed:
                        break
                    
                    sample = int(audio_array[i])
                    bit = sample & 1
                    extracted_bits += str(bit)
                    bit_count += 1
            
            else:  # 스테레오
                for i in range(len(audio_array)):
                    for ch in range(file_info['channels']):
                        if bit_count >= total_bits_needed:
                            break
                        
                        if channel == -1 or ch == channel:
                            sample = int(audio_array[i, ch])
                            bit = sample & 1
                            extracted_bits += str(bit)
                            bit_count += 1
                    
                    if bit_count >= total_bits_needed:
                        break
            
            # 메시지 부분만 추출 (길이 정보 제외)
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
            logger.error(f"LSB 오디오 추출 실패: {e}")
            return None
    
    def get_capacity(self, audio_path: str, channel: int = 0) -> int:
        """오디오의 LSB 임베딩 용량 반환 (바이트 단위)"""
        try:
            audio_array, file_info = self._read_wav_file(audio_path)
            if audio_array is None:
                return 0
            
            if file_info['channels'] == 1:
                total_samples = len(audio_array)
            else:
                if channel == -1:  # 모든 채널 사용
                    total_samples = len(audio_array) * file_info['channels']
                else:
                    total_samples = len(audio_array)
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, total_samples - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_audio_quality(self, original_path: str, stego_path: str) -> dict:
        """오디오 품질 분석 (SNR, THD+N 등)"""
        try:
            # 원본과 스테고 오디오 로드
            original_audio, original_info = self._read_wav_file(original_path)
            stego_audio, stego_info = self._read_wav_file(stego_path)
            
            if original_audio is None or stego_audio is None:
                return {}
            
            # SNR (Signal-to-Noise Ratio) 계산
            signal_power = np.mean(original_audio ** 2)
            noise_power = np.mean((stego_audio - original_audio) ** 2)
            
            if noise_power > 0:
                snr_db = 10 * np.log10(signal_power / noise_power)
            else:
                snr_db = float('inf')
            
            # RMS 분석
            original_rms = np.sqrt(np.mean(original_audio ** 2))
            stego_rms = np.sqrt(np.mean(stego_audio ** 2))
            rms_difference = abs(stego_rms - original_rms) / original_rms * 100
            
            # 동적 범위 분석
            original_dynamic_range = np.max(original_audio) - np.min(original_audio)
            stego_dynamic_range = np.max(stego_audio) - np.min(stego_audio)
            
            # 스펙트럼 분석 (간단 버전)
            original_spectrum = np.fft.fft(original_audio.flatten())
            stego_spectrum = np.fft.fft(stego_audio.flatten())
            
            spectrum_correlation = np.corrcoef(
                np.abs(original_spectrum), np.abs(stego_spectrum)
            )[0, 1]
            
            return {
                'SNR_dB': float(snr_db),
                'original_RMS': float(original_rms),
                'stego_RMS': float(stego_rms),
                'RMS_difference_percent': float(rms_difference),
                'original_dynamic_range': int(original_dynamic_range),
                'stego_dynamic_range': int(stego_dynamic_range),
                'spectrum_correlation': float(spectrum_correlation),
                'capacity_bytes': self.get_capacity(original_path),
                'audio_duration': original_info['duration'],
                'quality_assessment': 'Excellent' if snr_db > 60 else
                                   'Good' if snr_db > 40 else
                                   'Fair' if snr_db > 20 else 'Poor',
                'imperceptibility': 'High' if snr_db > 50 and spectrum_correlation > 0.99 else
                                  'Medium' if snr_db > 30 and spectrum_correlation > 0.95 else 'Low'
            }
            
        except Exception as e:
            logger.error(f"오디오 품질 분석 실패: {e}")
            return {}
    
    def create_test_audio(self, output_path: str, duration: float = 5.0,
                         frequency: float = 440.0) -> bool:
        """테스트용 오디오 파일 생성 (사인파)"""
        try:
            # 샘플 수 계산
            num_samples = int(self.sample_rate * duration)
            
            # 시간 배열 생성
            t = np.linspace(0, duration, num_samples)
            
            # 사인파 생성
            audio_signal = np.sin(2 * np.pi * frequency * t)
            
            # 진폭 스케일링 (16비트 범위)
            audio_signal = (audio_signal * self.max_amplitude * 0.8).astype(np.int16)
            
            # 스테레오인 경우
            if self.channels == 2:
                # 우측 채널은 약간 위상 지연
                right_channel = np.sin(2 * np.pi * frequency * t + np.pi/8)
                right_channel = (right_channel * self.max_amplitude * 0.8).astype(np.int16)
                
                # 스테레오 배열 생성
                stereo_audio = np.column_stack([audio_signal, right_channel])
                audio_signal = stereo_audio
            
            # 파일 정보 생성
            file_info = {
                'sample_rate': self.sample_rate,
                'channels': self.channels,
                'sample_width': self.sample_width,
                'frames': num_samples,
                'duration': duration
            }
            
            # WAV 파일로 저장
            success = self._write_wav_file(output_path, audio_signal, file_info)
            
            if success:
                logger.info(f"테스트 오디오 생성 완료: {output_path}")
                logger.info(f"주파수: {frequency}Hz, 길이: {duration}초")
            
            return success
            
        except Exception as e:
            logger.error(f"테스트 오디오 생성 실패: {e}")
            return False