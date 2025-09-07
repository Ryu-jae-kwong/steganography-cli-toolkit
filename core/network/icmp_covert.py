"""
ICMP 코버트 채널 모듈 v3.0

ICMP 프로토콜을 이용한 은닉 통신 기법들을 구현합니다:
- ICMP 페이로드 데이터 은닉
- ICMP 식별자/시퀀스 번호 조작
- ICMP 타입/코드 조작
- 핑 터널링
- ICMP 타이밍 조작
"""

import struct
import socket
import time
import threading
import queue
import random
import hashlib
from typing import List, Tuple, Dict, Optional, Union, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import select


class ICMPCovertChannel:
    """
    ICMP 코버트 채널 클래스
    
    ICMP 프로토콜을 이용하여 은닉 통신을 구현합니다.
    """
    
    def __init__(self):
        """클래스 초기화"""
        self.icmp_id = random.randint(1, 65535)
        self.sequence = 0
        self.packet_buffer = queue.Queue()
        self.is_listening = False
        
        # ICMP 타입 정의
        self.icmp_types = {
            'ECHO_REPLY': 0,
            'DEST_UNREACHABLE': 3,
            'SOURCE_QUENCH': 4,
            'REDIRECT': 5,
            'ECHO_REQUEST': 8,
            'TIME_EXCEEDED': 11,
            'PARAM_PROBLEM': 12,
            'TIMESTAMP_REQUEST': 13,
            'TIMESTAMP_REPLY': 14,
            'INFO_REQUEST': 15,
            'INFO_REPLY': 16
        }
        
        # 코버트 채널용 사용자 정의 타입 (실험용)
        self.covert_types = {
            'COVERT_DATA': 200,
            'COVERT_CONTROL': 201,
            'COVERT_ACK': 202
        }
    
    def send_covert_message(self, target_host: str, message: bytes,
                           method: str = 'payload', password: Optional[str] = None) -> bool:
        """
        ICMP를 통해 은닉 메시지를 전송합니다.
        
        Args:
            target_host: 대상 호스트
            message: 전송할 메시지
            method: 은닉 방법 ('payload', 'id_seq', 'type_code', 'timing')
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                message = self._encrypt_data(message, password)
            
            # 방법에 따라 전송
            if method == 'payload':
                return self._send_payload_covert(target_host, message)
            elif method == 'id_seq':
                return self._send_id_seq_covert(target_host, message)
            elif method == 'type_code':
                return self._send_type_code_covert(target_host, message)
            elif method == 'timing':
                return self._send_timing_covert(target_host, message)
            else:
                raise ValueError(f"지원하지 않는 방법입니다: {method}")
                
        except Exception as e:
            print(f"ICMP 코버트 전송 중 오류 발생: {str(e)}")
            return False
    
    def receive_covert_message(self, method: str = 'payload', 
                              password: Optional[str] = None,
                              timeout: int = 30) -> Optional[bytes]:
        """
        ICMP 코버트 메시지를 수신합니다.
        
        Args:
            method: 수신 방법
            password: 복호화 패스워드 (선택사항)
            timeout: 수신 타임아웃 (초)
            
        Returns:
            bytes: 수신된 메시지 또는 None
        """
        try:
            # ICMP 소켓 생성 및 수신 시작
            self.is_listening = True
            received_data = b''
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            
            start_time = time.time()
            
            while self.is_listening and (time.time() - start_time) < timeout:
                try:
                    packet, addr = sock.recvfrom(65535)
                    
                    # 방법에 따라 데이터 추출
                    if method == 'payload':
                        data_chunk = self._extract_payload_covert(packet)
                    elif method == 'id_seq':
                        data_chunk = self._extract_id_seq_covert(packet)
                    elif method == 'type_code':
                        data_chunk = self._extract_type_code_covert(packet)
                    elif method == 'timing':
                        data_chunk = self._extract_timing_covert(packet)
                    else:
                        continue
                    
                    if data_chunk:
                        received_data += data_chunk
                        
                        # 메시지 종료 확인 (특별한 마커 검색)
                        if b'\\x00\\x00\\x00\\x00' in received_data:
                            received_data = received_data.replace(b'\\x00\\x00\\x00\\x00', b'')
                            break
                            
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"패킷 수신 중 오류: {str(e)}")
                    continue
            
            sock.close()
            self.is_listening = False
            
            if not received_data:
                return None
            
            # 데이터 복호화 (필요시)
            if password:
                received_data = self._decrypt_data(received_data, password)
            
            return received_data
            
        except Exception as e:
            print(f"ICMP 코버트 수신 중 오류 발생: {str(e)}")
            return None
    
    def _send_payload_covert(self, target_host: str, message: bytes) -> bool:
        """페이로드에 데이터를 은닉하여 전송합니다."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # 메시지를 청크로 분할 (ICMP 페이로드 최대 크기 고려)
            chunk_size = 56  # 표준 ping 페이로드 크기
            
            for i in range(0, len(message), chunk_size):
                chunk = message[i:i + chunk_size]
                
                # 청크 크기가 부족하면 패딩
                if len(chunk) < chunk_size:
                    chunk = chunk.ljust(chunk_size, b'\\x00')
                
                # ICMP 패킷 생성
                packet = self._create_icmp_packet(self.icmp_types['ECHO_REQUEST'], 
                                                0, self.icmp_id, self.sequence, chunk)
                
                # 패킷 전송
                sock.sendto(packet, (target_host, 0))
                self.sequence += 1
                
                time.sleep(0.1)  # 패킷 간 간격
            
            # 종료 마커 전송
            end_marker = b'\\x00\\x00\\x00\\x00'.ljust(chunk_size, b'\\x00')
            packet = self._create_icmp_packet(self.icmp_types['ECHO_REQUEST'],
                                            0, self.icmp_id, self.sequence, end_marker)
            sock.sendto(packet, (target_host, 0))
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"페이로드 코버트 전송 중 오류: {str(e)}")
            return False
    
    def _send_id_seq_covert(self, target_host: str, message: bytes) -> bool:
        """ID와 시퀀스 번호에 데이터를 은닉하여 전송합니다."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            binary_data = self._bytes_to_binary(message)
            
            # 4바이트 (32비트)씩 처리 (ID 16비트 + 시퀀스 16비트)
            for i in range(0, len(binary_data), 32):
                chunk = binary_data[i:i + 32].ljust(32, '0')
                
                # 상위 16비트는 ID, 하위 16비트는 시퀀스에 임베딩
                embedded_id = int(chunk[:16], 2)
                embedded_seq = int(chunk[16:], 2)
                
                # ICMP 패킷 생성 (더미 페이로드)
                dummy_payload = b'\\x41' * 32  # 'A' 문자로 채움
                packet = self._create_icmp_packet(self.icmp_types['ECHO_REQUEST'],
                                                0, embedded_id, embedded_seq, 
                                                dummy_payload)
                
                sock.sendto(packet, (target_host, 0))
                time.sleep(0.05)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"ID/시퀀스 코버트 전송 중 오류: {str(e)}")
            return False
    
    def _send_type_code_covert(self, target_host: str, message: bytes) -> bool:
        """타입과 코드 필드에 데이터를 은닉하여 전송합니다."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            binary_data = self._bytes_to_binary(message)
            
            # 8비트씩 처리 (타입 4비트 + 코드 4비트, 실제로는 각각 8비트 사용)
            for i in range(0, len(binary_data), 8):
                chunk = binary_data[i:i + 8].ljust(8, '0')
                
                # 사용자 정의 ICMP 타입 사용
                icmp_type = self.covert_types['COVERT_DATA']
                icmp_code = int(chunk, 2)
                
                # ICMP 패킷 생성
                dummy_payload = b'\\x00' * 32
                packet = self._create_icmp_packet(icmp_type, icmp_code,
                                                self.icmp_id, self.sequence,
                                                dummy_payload)
                
                sock.sendto(packet, (target_host, 0))
                self.sequence += 1
                time.sleep(0.05)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"타입/코드 코버트 전송 중 오류: {str(e)}")
            return False
    
    def _send_timing_covert(self, target_host: str, message: bytes) -> bool:
        """패킷 전송 타이밍에 데이터를 은닉합니다."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            binary_data = self._bytes_to_binary(message)
            
            # 타이밍 간격 정의 (밀리초)
            short_interval = 0.05  # 0 비트
            long_interval = 0.15   # 1 비트
            
            for bit in binary_data:
                # 표준 ICMP 패킷 전송
                payload = b'\\x41' * 32
                packet = self._create_icmp_packet(self.icmp_types['ECHO_REQUEST'],
                                                0, self.icmp_id, self.sequence,
                                                payload)
                
                sock.sendto(packet, (target_host, 0))
                self.sequence += 1
                
                # 비트에 따라 다른 간격으로 대기
                if bit == '0':
                    time.sleep(short_interval)
                else:
                    time.sleep(long_interval)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"타이밍 코버트 전송 중 오류: {str(e)}")
            return False
    
    def _extract_payload_covert(self, packet: bytes) -> Optional[bytes]:
        """ICMP 페이로드에서 은닉 데이터를 추출합니다."""
        try:
            icmp_data = self._parse_icmp_packet(packet)
            if icmp_data and icmp_data['type'] == self.icmp_types['ECHO_REQUEST']:
                return icmp_data['payload']
            return None
            
        except Exception as e:
            print(f"페이로드 추출 중 오류: {str(e)}")
            return None
    
    def _extract_id_seq_covert(self, packet: bytes) -> Optional[bytes]:
        """ID와 시퀀스 번호에서 은닉 데이터를 추출합니다."""
        try:
            icmp_data = self._parse_icmp_packet(packet)
            if icmp_data and icmp_data['type'] == self.icmp_types['ECHO_REQUEST']:
                # ID와 시퀀스를 바이너리로 변환
                id_binary = format(icmp_data['id'], '016b')
                seq_binary = format(icmp_data['sequence'], '016b')
                
                binary_data = id_binary + seq_binary
                return self._binary_to_bytes(binary_data)
            
            return None
            
        except Exception as e:
            print(f"ID/시퀀스 추출 중 오류: {str(e)}")
            return None
    
    def _extract_type_code_covert(self, packet: bytes) -> Optional[bytes]:
        """타입과 코드에서 은닉 데이터를 추출합니다."""
        try:
            icmp_data = self._parse_icmp_packet(packet)
            if icmp_data and icmp_data['type'] == self.covert_types['COVERT_DATA']:
                # 코드 필드를 바이너리로 변환
                binary_data = format(icmp_data['code'], '08b')
                return self._binary_to_bytes(binary_data)
            
            return None
            
        except Exception as e:
            print(f"타입/코드 추출 중 오류: {str(e)}")
            return None
    
    def _extract_timing_covert(self, packet: bytes) -> Optional[bytes]:
        """타이밍 정보에서 은닉 데이터를 추출합니다."""
        # 타이밍 추출은 별도의 수신기에서 패킷 간격을 분석해야 함
        # 여기서는 표준 ICMP 패킷임을 확인만 함
        try:
            icmp_data = self._parse_icmp_packet(packet)
            if icmp_data and icmp_data['type'] == self.icmp_types['ECHO_REQUEST']:
                # 실제 구현에서는 패킷 수신 시간을 기록하고 분석
                return b'\\x01'  # 임시 반환값
            return None
            
        except Exception as e:
            print(f"타이밍 추출 중 오류: {str(e)}")
            return None
    
    def _create_icmp_packet(self, icmp_type: int, code: int, 
                           packet_id: int, sequence: int, payload: bytes) -> bytes:
        """ICMP 패킷을 생성합니다."""
        try:
            # 체크섬은 나중에 계산
            checksum = 0
            
            # ICMP 헤더 생성
            icmp_header = struct.pack('!BBHHH', icmp_type, code, checksum,
                                    packet_id, sequence)
            
            # 체크섬 계산
            checksum = self._calculate_checksum(icmp_header + payload)
            
            # 체크섬을 포함한 최종 헤더
            icmp_header = struct.pack('!BBHHH', icmp_type, code, checksum,
                                    packet_id, sequence)
            
            return icmp_header + payload
            
        except Exception as e:
            print(f"ICMP 패킷 생성 중 오류: {str(e)}")
            return b''
    
    def _parse_icmp_packet(self, packet: bytes) -> Optional[Dict[str, Any]]:
        """ICMP 패킷을 파싱합니다."""
        try:
            # IP 헤더 크기 계산
            if len(packet) < 20:
                return None
                
            ip_header_length = (packet[0] & 0x0F) * 4
            icmp_start = ip_header_length
            
            if len(packet) < icmp_start + 8:  # 최소 ICMP 헤더 크기
                return None
            
            # ICMP 헤더 파싱
            icmp_header = packet[icmp_start:icmp_start + 8]
            icmp_type, code, checksum, packet_id, sequence = struct.unpack('!BBHHH', icmp_header)
            
            # 페이로드 추출
            payload = packet[icmp_start + 8:]
            
            return {
                'type': icmp_type,
                'code': code,
                'checksum': checksum,
                'id': packet_id,
                'sequence': sequence,
                'payload': payload
            }
            
        except Exception as e:
            print(f"ICMP 패킷 파싱 중 오류: {str(e)}")
            return None
    
    def _calculate_checksum(self, data: bytes) -> int:
        """ICMP 체크섬을 계산합니다."""
        checksum = 0
        
        # 16비트 단위로 합계 계산
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                word = (data[i] << 8) + data[i + 1]
            else:
                word = data[i] << 8
            checksum += word
        
        # 캐리 비트 처리
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # 1의 보수 반환
        return ~checksum & 0xFFFF
    
    def analyze_covert_capacity(self, method: str) -> Dict[str, Union[int, str]]:
        """
        ICMP 코버트 채널의 용량을 분석합니다.
        
        Args:
            method: 분석할 방법
            
        Returns:
            dict: 분석 결과
        """
        analysis = {
            'method': method,
            'bits_per_packet': 0,
            'packets_per_second': 0,
            'bandwidth_bps': 0,
            'stealth_rating': 0,
            'detection_difficulty': 'Unknown'
        }
        
        if method == 'payload':
            analysis.update({
                'bits_per_packet': 448,  # 56바이트 * 8비트
                'packets_per_second': 10,
                'bandwidth_bps': 4480,
                'stealth_rating': 5,
                'detection_difficulty': 'Easy'
            })
            
        elif method == 'id_seq':
            analysis.update({
                'bits_per_packet': 32,  # ID(16) + 시퀀스(16)
                'packets_per_second': 20,
                'bandwidth_bps': 640,
                'stealth_rating': 8,
                'detection_difficulty': 'Hard'
            })
            
        elif method == 'type_code':
            analysis.update({
                'bits_per_packet': 8,  # 코드 필드 8비트
                'packets_per_second': 15,
                'bandwidth_bps': 120,
                'stealth_rating': 9,
                'detection_difficulty': 'Very Hard'
            })
            
        elif method == 'timing':
            analysis.update({
                'bits_per_packet': 1,  # 패킷당 1비트
                'packets_per_second': 8,  # 타이밍 간격 고려
                'bandwidth_bps': 8,
                'stealth_rating': 10,
                'detection_difficulty': 'Extremely Hard'
            })
        
        return analysis
    
    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """AES-256-GCM을 사용한 데이터 암호화"""
        try:
            # 패스워드에서 키 생성
            key = hashlib.sha256(password.encode('utf-8')).digest()
            
            # AES-GCM 암호화
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, auth_tag = cipher.encrypt_and_digest(data)
            
            return cipher.nonce + auth_tag + ciphertext
            
        except Exception as e:
            raise Exception(f"암호화 오류: {str(e)}")
    
    def _decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """AES-256-GCM을 사용한 데이터 복호화"""
        try:
            if len(encrypted_data) < 32:
                raise ValueError("암호화된 데이터가 너무 짧습니다")
            
            key = hashlib.sha256(password.encode('utf-8')).digest()
            
            nonce = encrypted_data[:16]
            auth_tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, auth_tag)
            
            return data
            
        except Exception as e:
            raise Exception(f"복호화 오류: {str(e)}")
    
    def _bytes_to_binary(self, data: bytes) -> str:
        """바이트를 바이너리 문자열로 변환"""
        return ''.join(format(byte, '08b') for byte in data)
    
    def _binary_to_bytes(self, binary_str: str) -> bytes:
        """바이너리 문자열을 바이트로 변환"""
        padding_length = 8 - (len(binary_str) % 8)
        if padding_length != 8:
            binary_str += '0' * padding_length
        
        bytes_list = []
        for i in range(0, len(binary_str), 8):
            byte_str = binary_str[i:i+8]
            if len(byte_str) == 8:
                bytes_list.append(int(byte_str, 2))
        
        return bytes(bytes_list)
    
    def stop_listening(self):
        """수신 중지"""
        self.is_listening = False


# 사용 예제
if __name__ == "__main__":
    # ICMP 코버트 채널 인스턴스 생성
    icmp_covert = ICMPCovertChannel()
    
    print("📡 ICMP 코버트 채널 테스트")
    print("=" * 50)
    
    # 각 방법별 용량 분석
    methods = ['payload', 'id_seq', 'type_code', 'timing']
    
    for method in methods:
        analysis = icmp_covert.analyze_covert_capacity(method)
        print(f"\n📊 {method.upper()} 방법 분석:")
        print(f"   패킷당 비트: {analysis['bits_per_packet']}")
        print(f"   초당 패킷: {analysis['packets_per_second']}")
        print(f"   대역폭: {analysis['bandwidth_bps']} bps")
        print(f"   은밀성 점수: {analysis['stealth_rating']}/10")
        print(f"   탐지 난이도: {analysis['detection_difficulty']}")
    
    print(f"\n💡 ICMP 코버트 채널 특징:")
    print("- 높은 대역폭: PAYLOAD 방법")
    print("- 높은 은밀성: TIMING 방법")
    print("- 균형: ID_SEQ 방법")
    print("- 방화벽 우회 가능성 높음")
    print("- 관리자 권한 필요")
    
    # 주의사항
    print(f"\n⚠️ 주의사항:")
    print("- Raw 소켓 사용으로 root 권한 필요")
    print("- 방화벽에서 차단될 수 있음")
    print("- 네트워크 모니터링 시 탐지 가능")
    print("- 교육 및 연구 목적으로만 사용")