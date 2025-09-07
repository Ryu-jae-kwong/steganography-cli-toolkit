"""
Echo Hiding 스테가노그래피 알고리즘

에코(잔향) 효과를 이용하여 데이터를 은닉하는 기법입니다.
원본 신호에 지연된 에코를 추가하여 0과 1을 서로 다른 지연 시간으로 표현합니다.
인간의 청각은 짧은 지연의 에코를 잘 인지하지 못한다는 특성을 이용합니다.

Reference: Gruhl et al. (1996), "Echo hiding"
"""

import numpy as np
import wave
import logging
from typing import Optional, Tuple, List
from ...utils.crypto import encrypt_message, decrypt_message

logger = logging.getLogger(__name__)


class EchoHidingSteganography:
    """Echo Hiding 스테가노그래피 구현"""
    
    def __init__(self, delay_0: float = 0.0005, delay_1: float = 0.001, 
                 decay_rate: float = 0.5, segment_length: float = 0.1):
        """
        Args:
            delay_0: 비트 '0'을 나타내는 에코 지연 시간 (초)
            delay_1: 비트 '1'을 나타내는 에코 지연 시간 (초)
            decay_rate: 에코 감쇠율 (0-1, 1에 가까울수록 에코가 강함)
            segment_length: 각 비트를 임베딩할 세그먼트 길이 (초)
        """
        self.delay_0 = delay_0
        self.delay_1 = delay_1
        self.decay_rate = decay_rate
        self.segment_length = segment_length
    
    def _read_wav_file(self, file_path: str) -> Tuple[np.ndarray, dict]:
        """WAV 파일 읽기 (LSB Audio와 동일한 구현)"""
        try:
            with wave.open(file_path, 'rb') as wav_file:
                frames = wav_file.getnframes()
                sample_rate = wav_file.getframerate()
                channels = wav_file.getnchannels()
                sample_width = wav_file.getsampwidth()
                
                audio_data = wav_file.readframes(frames)
                
                if sample_width == 1:
                    audio_array = np.frombuffer(audio_data, dtype=np.uint8)
                    audio_array = audio_array.astype(np.int16) - 128
                elif sample_width == 2:
                    audio_array = np.frombuffer(audio_data, dtype=np.int16)
                elif sample_width == 4:
                    audio_array = np.frombuffer(audio_data, dtype=np.int32)
                else:
                    raise ValueError(f"지원하지 않는 샘플 너비: {sample_width}")
                
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
        """WAV 파일 쓰기 (LSB Audio와 동일한 구현)"""
        try:
            with wave.open(file_path, 'wb') as wav_file:
                wav_file.setnchannels(file_info['channels'])
                wav_file.setsampwidth(file_info['sample_width'])
                wav_file.setframerate(file_info['sample_rate'])
                
                if file_info['sample_width'] == 1:
                    audio_data = (audio_array + 128).astype(np.uint8).tobytes()
                elif file_info['sample_width'] == 2:
                    audio_data = audio_array.astype(np.int16).tobytes()
                elif file_info['sample_width'] == 4:
                    audio_data = audio_array.astype(np.int32).tobytes()
                
                wav_file.writeframes(audio_data)
            
            return True
            
        except Exception as e:
            logger.error(f"WAV 파일 쓰기 실패 {file_path}: {e}")
            return False
    
    def _add_echo(self, signal: np.ndarray, delay_samples: int, 
                 decay: float) -> np.ndarray:
        """신호에 에코 추가"""
        echo_signal = np.zeros_like(signal)
        
        # 지연된 신호 생성
        if delay_samples < len(signal):
            echo_signal[delay_samples:] = signal[:-delay_samples] * decay
        
        # 원본 신호와 에코 신호 합성
        result = signal + echo_signal
        
        # 클리핑 방지
        max_val = np.max(np.abs(result))
        if max_val > 32767:  # 16비트 최대값
            result = result * (32767 / max_val)
        
        return result.astype(signal.dtype)
    
    def _segment_audio(self, audio_array: np.ndarray, sample_rate: int,
                      segment_length: float) -> List[np.ndarray]:
        """오디오를 세그먼트로 분할"""
        segment_samples = int(sample_rate * segment_length)
        segments = []
        
        for i in range(0, len(audio_array), segment_samples):
            segment = audio_array[i:i + segment_samples]
            
            # 세그먼트가 너무 작으면 패딩
            if len(segment) < segment_samples:
                if audio_array.ndim == 1:
                    padded = np.zeros(segment_samples, dtype=segment.dtype)
                    padded[:len(segment)] = segment
                else:
                    padded = np.zeros((segment_samples, audio_array.shape[1]), dtype=segment.dtype)
                    padded[:len(segment)] = segment
                segment = padded
            
            segments.append(segment)
        
        return segments
    
    def _detect_echo_delay(self, segment: np.ndarray, sample_rate: int) -> float:
        """세그먼트에서 에코 지연 시간 감지 (자기상관 함수 사용)"""
        try:
            # 모노 채널로 변환
            if segment.ndim == 2:
                mono_segment = np.mean(segment, axis=1)
            else:
                mono_segment = segment
            
            # 자기상관 함수 계산
            autocorr = np.correlate(mono_segment, mono_segment, mode='full')
            autocorr = autocorr[len(autocorr)//2:]
            
            # 가능한 지연 범위 설정
            min_delay_samples = int(sample_rate * 0.0001)  # 0.1ms
            max_delay_samples = int(sample_rate * 0.01)    # 10ms
            
            if max_delay_samples >= len(autocorr):
                max_delay_samples = len(autocorr) - 1
            
            # 첫 번째 피크 제외하고 최대 피크 찾기
            search_range = autocorr[min_delay_samples:max_delay_samples]
            
            if len(search_range) == 0:
                return 0.0
            
            peak_idx = np.argmax(search_range) + min_delay_samples
            detected_delay = peak_idx / sample_rate
            
            return detected_delay
            
        except Exception as e:
            logger.error(f"에코 지연 감지 실패: {e}")
            return 0.0
    
    def embed_message(self, input_path: str, message: str, output_path: str,
                     password: Optional[str] = None) -> bool:
        """Echo Hiding 방법으로 오디오에 메시지 임베딩"""
        try:
            # 오디오 파일 읽기
            audio_array, file_info = self._read_wav_file(input_path)
            if audio_array is None:
                return False
            
            sample_rate = file_info['sample_rate']
            logger.info(f"오디오 정보: {file_info['duration']:.2f}초, "
                       f"{sample_rate}Hz, {file_info['channels']}채널")
            
            # 메시지 암호화 (필요시)
            if password:
                encrypted_data = encrypt_message(message.encode('utf-8'), password)
                message_bits = ''.join(format(byte, '08b') for byte in encrypted_data)
            else:
                message_bytes = message.encode('utf-8')
                message_bits = ''.join(format(byte, '08b') for byte in message_bytes)
            
            # 메시지 길이 정보 추가
            length_bits = format(len(message_bits), '032b')
            total_bits = length_bits + message_bits
            
            logger.info(f"임베딩할 총 비트 수: {len(total_bits)}")
            
            # 오디오를 세그먼트로 분할
            segments = self._segment_audio(audio_array, sample_rate, self.segment_length)
            
            if len(segments) < len(total_bits):
                logger.error(f"오디오가 너무 짧습니다. 필요 세그먼트: {len(total_bits)}, "
                           f"가용 세그먼트: {len(segments)}")
                return False
            
            # 에코 지연 시간을 샘플 수로 변환
            delay_0_samples = int(sample_rate * self.delay_0)
            delay_1_samples = int(sample_rate * self.delay_1)
            
            # 각 세그먼트에 에코 추가
            modified_segments = []
            
            for i, segment in enumerate(segments):
                if i < len(total_bits):
                    bit = total_bits[i]
                    
                    if bit == '0':
                        delay_samples = delay_0_samples
                    else:  # bit == '1'
                        delay_samples = delay_1_samples
                    
                    # 에코 추가
                    if file_info['channels'] == 1:
                        modified_segment = self._add_echo(segment, delay_samples, self.decay_rate)
                    else:
                        # 스테레오의 경우 첫 번째 채널에만 에코 추가
                        modified_segment = segment.copy()
                        modified_segment[:, 0] = self._add_echo(
                            segment[:, 0], delay_samples, self.decay_rate
                        )
                    
                    modified_segments.append(modified_segment)
                else:
                    # 나머지 세그먼트는 원본 그대로
                    modified_segments.append(segment)
            
            # 세그먼트들을 다시 합성
            if file_info['channels'] == 1:
                stego_audio = np.concatenate(modified_segments)
            else:
                stego_audio = np.vstack(modified_segments)
            
            # 원본 길이에 맞추기
            if len(stego_audio) > len(audio_array):
                stego_audio = stego_audio[:len(audio_array)]
            
            # 결과 파일 저장
            success = self._write_wav_file(output_path, stego_audio, file_info)
            
            if success:
                logger.info(f"Echo Hiding 임베딩 완료: {output_path}")
                logger.info(f"사용된 세그먼트: {len(total_bits)}/{len(segments)}")
            
            return success
            
        except Exception as e:
            logger.error(f"Echo Hiding 임베딩 실패: {e}")
            return False
    
    def extract_message(self, input_path: str, password: Optional[str] = None) -> Optional[str]:
        """Echo Hiding 방법으로 오디오에서 메시지 추출"""
        try:
            # 오디오 파일 읽기
            audio_array, file_info = self._read_wav_file(input_path)
            if audio_array is None:
                return None
            
            sample_rate = file_info['sample_rate']
            
            # 오디오를 세그먼트로 분할
            segments = self._segment_audio(audio_array, sample_rate, self.segment_length)
            
            # 각 세그먼트에서 지연 시간 분석
            extracted_bits = []
            
            # 임계값 설정 (두 지연 시간의 중간값)
            threshold_delay = (self.delay_0 + self.delay_1) / 2
            
            for segment in segments:
                # 에코 지연 시간 감지
                detected_delay = self._detect_echo_delay(segment, sample_rate)
                
                # 감지된 지연에 따라 비트 판정
                if detected_delay < threshold_delay:
                    extracted_bits.append('0')
                else:
                    extracted_bits.append('1')
            
            # 메시지 길이 추출 (처음 32비트)
            if len(extracted_bits) < 32:
                logger.error("메시지 길이 정보를 읽을 수 없습니다")
                return None
            
            length_bits = ''.join(extracted_bits[:32])
            
            try:
                message_length = int(length_bits, 2)
                logger.info(f"추출된 메시지 길이: {message_length} 비트")
                
                if message_length <= 0 or message_length > len(extracted_bits) - 32:
                    logger.error("유효하지 않은 메시지 길이")
                    return None
            except ValueError:
                logger.error("길이 정보 파싱 실패")
                return None
            
            # 실제 메시지 추출
            if len(extracted_bits) < 32 + message_length:
                logger.error("메시지가 불완전합니다")
                return None
            
            message_bits = ''.join(extracted_bits[32:32 + message_length])
            
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
            logger.error(f"Echo Hiding 추출 실패: {e}")
            return None
    
    def get_capacity(self, audio_path: str) -> int:
        """오디오의 Echo Hiding 임베딩 용량 반환 (바이트 단위)"""
        try:
            audio_array, file_info = self._read_wav_file(audio_path)
            if audio_array is None:
                return 0
            
            # 세그먼트 수 계산
            total_segments = int(file_info['duration'] / self.segment_length)
            
            # 32비트는 길이 정보로 사용되므로 제외
            available_bits = max(0, total_segments - 32)
            return available_bits // 8
            
        except Exception as e:
            logger.error(f"용량 계산 실패: {e}")
            return 0
    
    def analyze_echo_parameters(self, stego_path: str) -> dict:
        """스테고 오디오의 에코 매개변수 분석"""
        try:
            audio_array, file_info = self._read_wav_file(stego_path)
            if audio_array is None:
                return {}
            
            sample_rate = file_info['sample_rate']
            segments = self._segment_audio(audio_array, sample_rate, self.segment_length)
            
            # 각 세그먼트의 에코 분석
            delay_detections = []
            echo_strengths = []
            
            for segment in segments:
                detected_delay = self._detect_echo_delay(segment, sample_rate)
                delay_detections.append(detected_delay)
                
                # 에코 강도 추정 (자기상관 최대값)
                if segment.ndim == 2:
                    mono_segment = np.mean(segment, axis=1)
                else:
                    mono_segment = segment
                
                autocorr = np.correlate(mono_segment, mono_segment, mode='full')
                autocorr = autocorr[len(autocorr)//2:]
                
                if len(autocorr) > 1:
                    echo_strength = np.max(autocorr[1:]) / autocorr[0] if autocorr[0] > 0 else 0
                else:
                    echo_strength = 0
                    
                echo_strengths.append(echo_strength)
            
            # 통계 계산
            delay_detections = np.array(delay_detections)
            echo_strengths = np.array(echo_strengths)
            
            # 지연 시간 클러스터링 (0과 1 비트 구분)
            threshold_delay = (self.delay_0 + self.delay_1) / 2
            bit_0_delays = delay_detections[delay_detections < threshold_delay]
            bit_1_delays = delay_detections[delay_detections >= threshold_delay]
            
            return {
                'total_segments': len(segments),
                'analyzed_segments': len(delay_detections),
                'avg_detected_delay': float(np.mean(delay_detections)),
                'std_detected_delay': float(np.std(delay_detections)),
                'avg_echo_strength': float(np.mean(echo_strengths)),
                'bit_0_count': len(bit_0_delays),
                'bit_1_count': len(bit_1_delays),
                'bit_0_avg_delay': float(np.mean(bit_0_delays)) if len(bit_0_delays) > 0 else 0.0,
                'bit_1_avg_delay': float(np.mean(bit_1_delays)) if len(bit_1_delays) > 0 else 0.0,
                'configured_delay_0': self.delay_0,
                'configured_delay_1': self.delay_1,
                'configured_decay_rate': self.decay_rate,
                'segment_length': self.segment_length,
                'capacity_bytes': self.get_capacity(stego_path),
                'detection_accuracy': 'Good' if np.std(delay_detections) < 0.0005 else
                                   'Fair' if np.std(delay_detections) < 0.001 else 'Poor'
            }
            
        except Exception as e:
            logger.error(f"에코 매개변수 분석 실패: {e}")
            return {}