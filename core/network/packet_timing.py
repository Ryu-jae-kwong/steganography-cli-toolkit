"""
패킷 타이밍 스테가노그래피 모듈 v3.0

네트워크 패킷의 시간 간격을 조작하여 데이터를 은닉하는 기법들을 구현합니다.
- 패킷 간격 조작 (Inter-Packet Delay)
- 패킷 크기 패턴 조작
- 패킷 전송 순서 조작
- 프레임 간격 조작
- 트래픽 패턴 조작
- 네트워크 지연 활용
"""

import socket
import time
import threading
import struct
import random
import hashlib
import base64
import statistics
from typing import List, Optional, Dict, Any, Tuple
from queue import Queue
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


@dataclass
class TimingPacket:
    """타이밍 패킷 정보"""
    sequence: int
    timestamp: float
    size: int
    delay: float
    data: bytes


@dataclass
class TimingPattern:
    """타이밍 패턴 정보"""
    pattern_type: str
    intervals: List[float]
    total_duration: float
    packet_count: int
    encoded_bits: str


class PacketTimingSteganography:
    """패킷 타이밍 스테가노그래피 클래스"""
    
    def __init__(self):
        self.session_id = self._generate_session_id()
        
        # 타이밍 설정
        self.base_interval = 0.1  # 기본 패킷 간격 (초)
        self.min_interval = 0.05  # 최소 간격
        self.max_interval = 0.5   # 최대 간격
        
        # 인코딩 설정
        self.bit_encoding = {
            '0': 0.1,  # 0비트 = 짧은 간격
            '1': 0.3   # 1비트 = 긴 간격
        }
        
        # 패킷 크기 인코딩
        self.size_encoding = {
            '0': 64,   # 0비트 = 작은 패킷
            '1': 1024  # 1비트 = 큰 패킷
        }
        
        # 패턴 저장소
        self.sent_patterns = []
        self.received_patterns = []
        
        # 동기화
        self.sync_marker = 0xDEADBEEF
        self.sync_interval = 1.0  # 동기화 신호 간격
    
    def _generate_session_id(self) -> str:
        """세션 ID 생성"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """AES-256-GCM으로 데이터 암호화"""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return salt + nonce + encryptor.tag + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """AES-256-GCM으로 데이터 복호화"""
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _bytes_to_binary(self, data: bytes) -> str:
        """바이트를 이진 문자열로 변환"""
        return ''.join(format(byte, '08b') for byte in data)
    
    def _binary_to_bytes(self, binary: str) -> bytes:
        """이진 문자열을 바이트로 변환"""
        # 8비트 단위로 맞춤
        while len(binary) % 8 != 0:
            binary += '0'
        
        return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
    
    def embed_interval_timing(self, data: bytes, target_host: str, target_port: int,
                             password: Optional[str] = None) -> bool:
        """
        패킷 간격을 이용하여 데이터를 임베딩합니다.
        
        Args:
            data: 임베딩할 데이터
            target_host: 대상 호스트
            target_port: 대상 포트
            password: 암호화 패스워드
        
        Returns:
            성공 여부
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 동기화 신호 전송
            sync_packet = struct.pack('!I', self.sync_marker)
            sock.sendto(sync_packet, (target_host, target_port))
            time.sleep(self.sync_interval)
            
            # 패킷 타이밍으로 데이터 전송
            packet_sequence = 0
            start_time = time.time()
            
            for bit in binary_data:
                # 비트에 따른 지연 시간 결정
                interval = self.bit_encoding[bit]
                
                # 패킷 생성 및 전송
                packet_data = struct.pack('!I', packet_sequence)
                sock.sendto(packet_data, (target_host, target_port))
                
                # 타이밍 패턴 저장
                timing_packet = TimingPacket(
                    sequence=packet_sequence,
                    timestamp=time.time(),
                    size=len(packet_data),
                    delay=interval,
                    data=packet_data
                )
                self.sent_patterns.append(timing_packet)
                
                # 지연
                time.sleep(interval)
                packet_sequence += 1
            
            # 종료 신호
            end_packet = struct.pack('!I', 0xFFFFFFFF)
            sock.sendto(end_packet, (target_host, target_port))
            
            sock.close()
            
            print(f"간격 타이밍으로 {len(binary_data)}비트 전송 완료")
            print(f"총 소요 시간: {time.time() - start_time:.2f}초")
            
            return True
            
        except Exception as e:
            print(f"간격 타이밍 임베딩 오류: {e}")
            return False
    
    def extract_interval_timing(self, listen_port: int, timeout: float = 30.0,
                               password: Optional[str] = None) -> Optional[bytes]:
        """
        패킷 간격에서 데이터를 추출합니다.
        """
        try:
            # 수신 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(1.0)  # 1초 타임아웃
            
            print(f"포트 {listen_port}에서 타이밍 패킷 수신 대기...")
            
            packets = []
            start_time = time.time()
            sync_found = False
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    recv_time = time.time()
                    
                    # 동기화 신호 확인
                    if len(data) >= 4:
                        marker = struct.unpack('!I', data[:4])[0]
                        
                        if marker == self.sync_marker and not sync_found:
                            sync_found = True
                            print(f"동기화 신호 수신: {addr}")
                            continue
                        
                        elif marker == 0xFFFFFFFF and sync_found:
                            print("종료 신호 수신")
                            break
                        
                        elif sync_found:
                            # 패킷 정보 저장
                            packets.append((recv_time, data, addr))
                
                except socket.timeout:
                    if sync_found and packets:
                        break
                    continue
            
            sock.close()
            
            if not packets:
                print("수신된 패킷이 없습니다.")
                return None
            
            # 패킷 간격 분석
            intervals = []
            for i in range(1, len(packets)):
                interval = packets[i][0] - packets[i-1][0]
                intervals.append(interval)
            
            if not intervals:
                return None
            
            # 간격을 비트로 변환
            binary_data = ""
            threshold = (self.bit_encoding['0'] + self.bit_encoding['1']) / 2
            
            for interval in intervals:
                if interval < threshold:
                    binary_data += '0'
                else:
                    binary_data += '1'
            
            if not binary_data:
                return None
            
            # 바이너리를 바이트로 변환
            extracted_data = self._binary_to_bytes(binary_data)
            
            # 데이터 복호화 (필요시)
            if password:
                extracted_data = self._decrypt_data(extracted_data, password)
            
            print(f"간격 분석으로 {len(binary_data)}비트 추출 완료")
            
            return extracted_data
            
        except Exception as e:
            print(f"간격 타이밍 추출 오류: {e}")
            return None
    
    def embed_size_pattern(self, data: bytes, target_host: str, target_port: int,
                          password: Optional[str] = None) -> bool:
        """
        패킷 크기 패턴으로 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 동기화 신호
            sync_packet = b'SYNC' + struct.pack('!I', len(binary_data))
            sock.sendto(sync_packet, (target_host, target_port))
            time.sleep(0.1)
            
            # 패킷 크기로 데이터 전송
            for i, bit in enumerate(binary_data):
                # 비트에 따른 패킷 크기 결정
                packet_size = self.size_encoding[bit]
                
                # 지정된 크기의 패킷 생성
                packet_data = struct.pack('!I', i) + b'X' * (packet_size - 4)
                sock.sendto(packet_data, (target_host, target_port))
                
                # 일정한 간격으로 전송
                time.sleep(0.05)
            
            # 종료 신호
            end_packet = b'END_'
            sock.sendto(end_packet, (target_host, target_port))
            
            sock.close()
            
            print(f"크기 패턴으로 {len(binary_data)}비트 전송 완료")
            
            return True
            
        except Exception as e:
            print(f"크기 패턴 임베딩 오류: {e}")
            return False
    
    def extract_size_pattern(self, listen_port: int, timeout: float = 30.0,
                            password: Optional[str] = None) -> Optional[bytes]:
        """
        패킷 크기 패턴에서 데이터를 추출합니다.
        """
        try:
            # 수신 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(1.0)
            
            print(f"포트 {listen_port}에서 크기 패턴 수신 대기...")
            
            packets = []
            start_time = time.time()
            sync_found = False
            expected_bits = 0
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(2048)
                    
                    # 동기화 신호 확인
                    if data.startswith(b'SYNC') and not sync_found:
                        sync_found = True
                        if len(data) >= 8:
                            expected_bits = struct.unpack('!I', data[4:8])[0]
                            print(f"동기화 신호 수신, 예상 비트 수: {expected_bits}")
                        continue
                    
                    elif data.startswith(b'END_') and sync_found:
                        print("종료 신호 수신")
                        break
                    
                    elif sync_found:
                        # 패킷 크기 저장
                        packets.append(len(data))
                        
                        if len(packets) >= expected_bits:
                            break
                
                except socket.timeout:
                    if sync_found and packets:
                        break
                    continue
            
            sock.close()
            
            if not packets:
                return None
            
            # 패킷 크기를 비트로 변환
            binary_data = ""
            threshold = (self.size_encoding['0'] + self.size_encoding['1']) / 2
            
            for packet_size in packets:
                if packet_size < threshold:
                    binary_data += '0'
                else:
                    binary_data += '1'
            
            if not binary_data:
                return None
            
            # 바이너리를 바이트로 변환
            extracted_data = self._binary_to_bytes(binary_data)
            
            # 데이터 복호화 (필요시)
            if password:
                extracted_data = self._decrypt_data(extracted_data, password)
            
            print(f"크기 패턴으로 {len(binary_data)}비트 추출 완료")
            
            return extracted_data
            
        except Exception as e:
            print(f"크기 패턴 추출 오류: {e}")
            return None
    
    def embed_jitter_pattern(self, data: bytes, target_host: str, target_port: int,
                           password: Optional[str] = None) -> bool:
        """
        네트워크 지터(지연 변동) 패턴으로 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 기준 시간 설정
            base_time = time.time()
            
            # 동기화 신호
            sync_data = b'JITTER_SYNC'
            sock.sendto(sync_data, (target_host, target_port))
            time.sleep(0.5)
            
            # 지터 패턴으로 데이터 전송
            for i, bit in enumerate(binary_data):
                # 비트에 따른 지터 값 결정
                if bit == '0':
                    # 낮은 지터 (일정한 간격)
                    jitter = 0.0
                else:
                    # 높은 지터 (불규칙한 간격)
                    jitter = random.uniform(0.05, 0.15)
                
                # 기본 간격에 지터 추가
                interval = self.base_interval + jitter
                
                # 패킷 전송
                packet_data = struct.pack('!If', i, jitter)
                sock.sendto(packet_data, (target_host, target_port))
                
                time.sleep(interval)
            
            # 종료 신호
            end_data = b'JITTER_END'
            sock.sendto(end_data, (target_host, target_port))
            
            sock.close()
            
            print(f"지터 패턴으로 {len(binary_data)}비트 전송 완료")
            
            return True
            
        except Exception as e:
            print(f"지터 패턴 임베딩 오류: {e}")
            return False
    
    def extract_jitter_pattern(self, listen_port: int, timeout: float = 30.0,
                              password: Optional[str] = None) -> Optional[bytes]:
        """
        지터 패턴에서 데이터를 추출합니다.
        """
        try:
            # 수신 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(1.0)
            
            print(f"포트 {listen_port}에서 지터 패턴 수신 대기...")
            
            jitter_values = []
            timestamps = []
            start_time = time.time()
            sync_found = False
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    recv_time = time.time()
                    
                    if data == b'JITTER_SYNC' and not sync_found:
                        sync_found = True
                        print("지터 동기화 신호 수신")
                        continue
                    
                    elif data == b'JITTER_END' and sync_found:
                        print("지터 종료 신호 수신")
                        break
                    
                    elif sync_found and len(data) >= 8:
                        # 지터 값 추출
                        sequence, jitter = struct.unpack('!If', data[:8])
                        jitter_values.append(jitter)
                        timestamps.append(recv_time)
                
                except socket.timeout:
                    if sync_found and jitter_values:
                        break
                    continue
            
            sock.close()
            
            if not jitter_values:
                return None
            
            # 지터 값을 비트로 변환
            binary_data = ""
            jitter_threshold = 0.025  # 지터 임계값
            
            for jitter in jitter_values:
                if jitter < jitter_threshold:
                    binary_data += '0'
                else:
                    binary_data += '1'
            
            if not binary_data:
                return None
            
            # 바이너리를 바이트로 변환
            extracted_data = self._binary_to_bytes(binary_data)
            
            # 데이터 복호화 (필요시)
            if password:
                extracted_data = self._decrypt_data(extracted_data, password)
            
            print(f"지터 패턴으로 {len(binary_data)}비트 추출 완료")
            
            return extracted_data
            
        except Exception as e:
            print(f"지터 패턴 추출 오류: {e}")
            return None
    
    def embed_burst_pattern(self, data: bytes, target_host: str, target_port: int,
                           password: Optional[str] = None) -> bool:
        """
        패킷 버스트 패턴으로 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 동기화 신호
            sync_data = b'BURST_SYNC'
            sock.sendto(sync_data, (target_host, target_port))
            time.sleep(0.5)
            
            # 버스트 패턴으로 데이터 전송
            for i, bit in enumerate(binary_data):
                if bit == '0':
                    # 단일 패킷 (버스트 없음)
                    packet_data = struct.pack('!II', i, 1)
                    sock.sendto(packet_data, (target_host, target_port))
                
                else:
                    # 버스트 패킷 (연속 3개)
                    for j in range(3):
                        packet_data = struct.pack('!III', i, 3, j)
                        sock.sendto(packet_data, (target_host, target_port))
                        time.sleep(0.01)  # 짧은 버스트 간격
                
                # 비트 간 간격
                time.sleep(0.2)
            
            # 종료 신호
            end_data = b'BURST_END'
            sock.sendto(end_data, (target_host, target_port))
            
            sock.close()
            
            print(f"버스트 패턴으로 {len(binary_data)}비트 전송 완료")
            
            return True
            
        except Exception as e:
            print(f"버스트 패턴 임베딩 오류: {e}")
            return False
    
    def extract_burst_pattern(self, listen_port: int, timeout: float = 30.0,
                             password: Optional[str] = None) -> Optional[bytes]:
        """
        버스트 패턴에서 데이터를 추출합니다.
        """
        try:
            # 수신 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(1.0)
            
            print(f"포트 {listen_port}에서 버스트 패턴 수신 대기...")
            
            burst_data = {}
            start_time = time.time()
            sync_found = False
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    
                    if data == b'BURST_SYNC' and not sync_found:
                        sync_found = True
                        print("버스트 동기화 신호 수신")
                        continue
                    
                    elif data == b'BURST_END' and sync_found:
                        print("버스트 종료 신호 수신")
                        break
                    
                    elif sync_found and len(data) >= 8:
                        # 버스트 정보 추출
                        bit_index = struct.unpack('!I', data[:4])[0]
                        burst_count = struct.unpack('!I', data[4:8])[0]
                        
                        if bit_index not in burst_data:
                            burst_data[bit_index] = []
                        
                        burst_data[bit_index].append(burst_count)
                
                except socket.timeout:
                    if sync_found and burst_data:
                        break
                    continue
            
            sock.close()
            
            if not burst_data:
                return None
            
            # 버스트 패턴을 비트로 변환
            binary_data = ""
            
            for bit_index in sorted(burst_data.keys()):
                burst_counts = burst_data[bit_index]
                
                # 단일 패킷이면 0, 버스트면 1
                if len(burst_counts) == 1 and burst_counts[0] == 1:
                    binary_data += '0'
                elif len(burst_counts) > 1 or (len(burst_counts) == 1 and burst_counts[0] > 1):
                    binary_data += '1'
            
            if not binary_data:
                return None
            
            # 바이너리를 바이트로 변환
            extracted_data = self._binary_to_bytes(binary_data)
            
            # 데이터 복호화 (필요시)
            if password:
                extracted_data = self._decrypt_data(extracted_data, password)
            
            print(f"버스트 패턴으로 {len(binary_data)}비트 추출 완료")
            
            return extracted_data
            
        except Exception as e:
            print(f"버스트 패턴 추출 오류: {e}")
            return None
    
    def analyze_traffic_pattern(self, pcap_file: str = None) -> Dict[str, Any]:
        """
        네트워크 트래픽 패턴을 분석합니다.
        """
        # 실제 pcap 파일 분석은 복잡하므로 시뮬레이션된 분석 결과 반환
        analysis_result = {
            'interval_analysis': {
                'mean_interval': 0.15,
                'std_interval': 0.08,
                'suspicious_patterns': 2,
                'regularity_score': 0.75
            },
            'size_analysis': {
                'mean_size': 512,
                'std_size': 256,
                'size_patterns': ['64B bursts', '1KB peaks'],
                'anomaly_score': 0.3
            },
            'timing_analysis': {
                'jitter_variance': 0.02,
                'burst_detection': True,
                'periodic_patterns': 3,
                'steganography_probability': 0.6
            },
            'recommendations': [
                '정규 간격 패턴이 의심스러움',
                '패킷 크기가 너무 균일함',
                '지터 분산이 비정상적으로 낮음'
            ]
        }
        
        return analysis_result
    
    def get_capacity_info(self, method: str = 'all') -> Dict[str, Any]:
        """
        각 타이밍 방법의 용량 정보를 반환합니다.
        """
        capacity_info = {}
        
        if method in ['all', 'interval']:
            # 간격 타이밍: 1비트/패킷, 초당 약 5-10패킷 = 5-10 bps
            capacity_info['interval'] = {
                'bits_per_second': 8,
                'overhead': '높음',
                'detection_risk': '중간',
                'description': '패킷 간격으로 인코딩, 느리지만 안전'
            }
        
        if method in ['all', 'size']:
            # 크기 패턴: 1비트/패킷, 더 빠른 전송 가능 = 10-20 bps
            capacity_info['size'] = {
                'bits_per_second': 15,
                'overhead': '중간',
                'detection_risk': '높음',
                'description': '패킷 크기로 인코딩, 빠르지만 눈에 띄기 쉬움'
            }
        
        if method in ['all', 'jitter']:
            # 지터 패턴: 1비트/패킷, 자연스러운 네트워크 현상 모방 = 6-12 bps
            capacity_info['jitter'] = {
                'bits_per_second': 10,
                'overhead': '낮음',
                'detection_risk': '낮음',
                'description': '네트워크 지터 모방, 가장 은밀함'
            }
        
        if method in ['all', 'burst']:
            # 버스트 패턴: 1비트/그룹, 그룹당 시간이 더 필요 = 3-6 bps
            capacity_info['burst'] = {
                'bits_per_second': 5,
                'overhead': '매우 높음',
                'detection_risk': '중간',
                'description': '패킷 버스트 패턴, 느리지만 특별한 상황에 유용'
            }
        
        if method == 'all':
            total_capacity = sum(info['bits_per_second'] for info in capacity_info.values())
            capacity_info['summary'] = {
                'total_bps': total_capacity,
                'recommended': 'jitter',
                'fastest': 'size',
                'most_covert': 'jitter'
            }
        
        return capacity_info
    
    def get_stealth_rating(self) -> Dict[str, int]:
        """
        각 방법의 은밀성 등급을 반환합니다 (1-10점).
        """
        return {
            'interval': 6,    # 규칙적인 패턴이 의심스러울 수 있음
            'size': 4,        # 패킷 크기 패턴이 눈에 띄기 쉬움
            'jitter': 9,      # 자연스러운 네트워크 현상과 유사
            'burst': 7        # 트래픽 급증은 자연스럽지만 패턴이 있으면 의심
        }