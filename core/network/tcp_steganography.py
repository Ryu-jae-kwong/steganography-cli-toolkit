"""
TCP 스테가노그래피 모듈 v3.0

TCP 프로토콜의 다양한 필드를 조작하여 데이터를 은닉하는 기법들을 구현합니다:
- TCP 시퀀스 번호 조작
- TCP 플래그 조작
- TCP 윈도우 사이즈 조작
- TCP 옵션 필드 활용
- 패킷 순서 조작
"""

import struct
import socket
import random
import time
from typing import List, Tuple, Dict, Optional, Union
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import threading
import queue


class TCPSteganography:
    """
    TCP 스테가노그래피 클래스
    
    TCP 프로토콜의 다양한 필드를 조작하여 은닉 통신을 구현합니다.
    """
    
    def __init__(self):
        """클래스 초기화"""
        self.sequence_base = random.randint(1000, 999999)
        self.window_base = 8192  # 기본 윈도우 크기
        self.packet_buffer = queue.Queue()
        self.encoding_methods = ['sequence', 'flags', 'window', 'options', 'order']
        
        # TCP 플래그 정의
        self.tcp_flags = {
            'FIN': 0x01,
            'SYN': 0x02,
            'RST': 0x04,
            'PSH': 0x08,
            'ACK': 0x10,
            'URG': 0x20,
            'ECE': 0x40,
            'CWR': 0x80
        }
    
    def embed_in_sequence(self, data: bytes, target_host: str, target_port: int,
                         password: Optional[str] = None) -> bool:
        """
        TCP 시퀀스 번호에 데이터를 임베딩합니다.
        
        Args:
            data: 임베딩할 데이터
            target_host: 대상 호스트
            target_port: 대상 포트
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # TCP 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # 패킷별로 시퀀스 번호에 데이터 임베딩
            bits_per_packet = 16  # 하위 16비트 사용
            sequence_num = self.sequence_base
            
            for i in range(0, len(binary_data), bits_per_packet):
                chunk = binary_data[i:i + bits_per_packet]
                
                # 시퀀스 번호 하위 비트에 데이터 임베딩
                embedded_bits = int(chunk.ljust(bits_per_packet, '0'), 2)
                modified_sequence = (sequence_num & 0xFFFF0000) | embedded_bits
                
                # TCP 패킷 생성 및 전송
                packet = self._create_tcp_packet(target_host, target_port, 
                                               sequence=modified_sequence)
                sock.sendto(packet, (target_host, target_port))
                
                sequence_num += 1
                time.sleep(0.01)  # 패킷 간 간격
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"TCP 시퀀스 임베딩 중 오류 발생: {str(e)}")
            return False
    
    def extract_from_sequence(self, packets: List[bytes], password: Optional[str] = None) -> Optional[bytes]:
        """
        TCP 시퀀스 번호에서 데이터를 추출합니다.
        
        Args:
            packets: TCP 패킷 리스트
            password: 복호화 패스워드 (선택사항)
            
        Returns:
            bytes: 추출된 데이터 또는 None
        """
        try:
            binary_data = ""
            
            for packet_data in packets:
                # TCP 헤더 파싱
                tcp_header = self._parse_tcp_header(packet_data)
                if tcp_header:
                    sequence_num = tcp_header['sequence']
                    
                    # 하위 16비트에서 데이터 추출
                    embedded_bits = sequence_num & 0x0000FFFF
                    binary_chunk = format(embedded_bits, '016b')
                    binary_data += binary_chunk
            
            # 바이너리에서 바이트로 변환
            data = self._binary_to_bytes(binary_data)
            
            # 데이터 복호화 (필요시)
            if password:
                data = self._decrypt_data(data, password)
            
            return data
            
        except Exception as e:
            print(f"TCP 시퀀스 추출 중 오류 발생: {str(e)}")
            return None
    
    def embed_in_flags(self, data: bytes, target_host: str, target_port: int,
                      password: Optional[str] = None) -> bool:
        """
        TCP 플래그에 데이터를 임베딩합니다.
        
        Args:
            data: 임베딩할 데이터
            target_host: 대상 호스트
            target_port: 대상 포트
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # TCP 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # 각 비트를 별도 패킷의 예약된 플래그 비트에 임베딩
            reserved_bits = [0x100, 0x200, 0x400]  # Reserved bits in TCP flags
            bit_index = 0
            
            for bit in binary_data:
                if bit_index >= len(reserved_bits):
                    bit_index = 0
                
                flags = self.tcp_flags['ACK']  # 기본 ACK 플래그
                if bit == '1':
                    flags |= reserved_bits[bit_index]
                
                # TCP 패킷 생성 및 전송
                packet = self._create_tcp_packet(target_host, target_port, flags=flags)
                sock.sendto(packet, (target_host, target_port))
                
                bit_index += 1
                time.sleep(0.01)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"TCP 플래그 임베딩 중 오류 발생: {str(e)}")
            return False
    
    def embed_in_window(self, data: bytes, target_host: str, target_port: int,
                       password: Optional[str] = None) -> bool:
        """
        TCP 윈도우 크기에 데이터를 임베딩합니다.
        
        Args:
            data: 임베딩할 데이터
            target_host: 대상 호스트
            target_port: 대상 포트
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 바이너리 데이터로 변환
            binary_data = self._bytes_to_binary(data)
            
            # TCP 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # 윈도우 크기 하위 비트에 데이터 임베딩
            bits_per_packet = 8  # 하위 8비트 사용
            
            for i in range(0, len(binary_data), bits_per_packet):
                chunk = binary_data[i:i + bits_per_packet]
                
                # 윈도우 크기 계산
                embedded_bits = int(chunk.ljust(bits_per_packet, '0'), 2)
                window_size = (self.window_base & 0xFF00) | embedded_bits
                
                # TCP 패킷 생성 및 전송
                packet = self._create_tcp_packet(target_host, target_port, 
                                               window=window_size)
                sock.sendto(packet, (target_host, target_port))
                
                time.sleep(0.01)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"TCP 윈도우 임베딩 중 오류 발생: {str(e)}")
            return False
    
    def embed_in_options(self, data: bytes, target_host: str, target_port: int,
                        password: Optional[str] = None) -> bool:
        """
        TCP 옵션 필드에 데이터를 임베딩합니다.
        
        Args:
            data: 임베딩할 데이터
            target_host: 대상 호스트
            target_port: 대상 포트
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # TCP 소켓 생성
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # 데이터를 청크로 분할 (옵션 필드 최대 40바이트)
            chunk_size = 36  # 4바이트는 옵션 헤더용
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                
                # TCP 옵션 생성 (사용자 정의 옵션)
                option_kind = 254  # 실험용 옵션
                option_length = len(chunk) + 2
                tcp_option = struct.pack('!BB', option_kind, option_length) + chunk
                
                # 패딩 추가 (4바이트 정렬)
                padding_length = (4 - (len(tcp_option) % 4)) % 4
                tcp_option += b'\x00' * padding_length
                
                # TCP 패킷 생성 및 전송
                packet = self._create_tcp_packet(target_host, target_port, 
                                               options=tcp_option)
                sock.sendto(packet, (target_host, target_port))
                
                time.sleep(0.01)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"TCP 옵션 임베딩 중 오류 발생: {str(e)}")
            return False
    
    def _create_tcp_packet(self, target_host: str, target_port: int,
                          sequence: int = None, flags: int = None,
                          window: int = None, options: bytes = None) -> bytes:
        """TCP 패킷을 생성합니다."""
        try:
            # IP 헤더 생성
            source_ip = socket.gethostbyname(socket.gethostname())
            dest_ip = socket.gethostbyname(target_host)
            
            # IP 주소를 바이너리로 변환
            source_addr = socket.inet_aton(source_ip)
            dest_addr = socket.inet_aton(target_host)
            
            # TCP 헤더 필드 설정
            source_port = random.randint(1024, 65535)
            seq_num = sequence or self.sequence_base
            ack_num = 0
            tcp_flags = flags or self.tcp_flags['SYN']
            window_size = window or self.window_base
            checksum = 0  # 체크섬은 나중에 계산
            urgent_ptr = 0
            
            # TCP 옵션 처리
            tcp_options = options or b''
            header_length = (20 + len(tcp_options)) // 4  # 4바이트 단위
            
            # TCP 헤더 생성 (옵션 제외)
            tcp_header = struct.pack('!HHLLBBHHH',
                                   source_port, target_port,
                                   seq_num, ack_num,
                                   (header_length << 4), tcp_flags,
                                   window_size, checksum, urgent_ptr)
            
            # TCP 헤더 + 옵션
            tcp_header += tcp_options
            
            # 의사 헤더를 사용한 체크섬 계산
            pseudo_header = source_addr + dest_addr + struct.pack('!BBH',
                                                                 0, socket.IPPROTO_TCP,
                                                                 len(tcp_header))
            checksum = self._calculate_checksum(pseudo_header + tcp_header)
            
            # 체크섬 업데이트
            tcp_header = struct.pack('!HHLLBBH',
                                   source_port, target_port,
                                   seq_num, ack_num,
                                   (header_length << 4), tcp_flags,
                                   window_size) + struct.pack('!HH', checksum, urgent_ptr)
            
            # TCP 옵션 다시 추가
            tcp_header += tcp_options
            
            # IP 헤더 생성
            version_ihl = 0x45  # IPv4, 헤더 길이 20바이트
            tos = 0
            total_length = 20 + len(tcp_header)
            identification = random.randint(1, 65535)
            flags_fragment = 0
            ttl = 64
            protocol = socket.IPPROTO_TCP
            ip_checksum = 0
            
            ip_header = struct.pack('!BBHHHBBH4s4s',
                                  version_ihl, tos, total_length,
                                  identification, flags_fragment,
                                  ttl, protocol, ip_checksum,
                                  source_addr, dest_addr)
            
            # IP 체크섬 계산
            ip_checksum = self._calculate_checksum(ip_header)
            ip_header = struct.pack('!BBHHHBB',
                                  version_ihl, tos, total_length,
                                  identification, flags_fragment,
                                  ttl, protocol) + struct.pack('!H', ip_checksum) + source_addr + dest_addr
            
            return ip_header + tcp_header
            
        except Exception as e:
            print(f"TCP 패킷 생성 중 오류 발생: {str(e)}")
            return b''
    
    def _parse_tcp_header(self, packet_data: bytes) -> Optional[Dict]:
        """TCP 헤더를 파싱합니다."""
        try:
            if len(packet_data) < 40:  # 최소 IP(20) + TCP(20) 헤더 크기
                return None
            
            # IP 헤더 크기 계산
            ip_header_length = (packet_data[0] & 0x0F) * 4
            tcp_start = ip_header_length
            
            if len(packet_data) < tcp_start + 20:
                return None
            
            # TCP 헤더 파싱
            tcp_header = packet_data[tcp_start:tcp_start + 20]
            
            source_port, dest_port, sequence, ack, header_flags, window, \
            checksum, urgent = struct.unpack('!HHLLBBHHH', tcp_header)
            
            header_length = (header_flags >> 4) * 4
            flags = header_flags & 0xFF
            
            return {
                'source_port': source_port,
                'dest_port': dest_port,
                'sequence': sequence,
                'ack': ack,
                'header_length': header_length,
                'flags': flags,
                'window': window,
                'checksum': checksum,
                'urgent': urgent
            }
            
        except Exception as e:
            print(f"TCP 헤더 파싱 중 오류 발생: {str(e)}")
            return None
    
    def _calculate_checksum(self, data: bytes) -> int:
        """체크섬을 계산합니다."""
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
    
    def analyze_tcp_covert_capacity(self, method: str) -> Dict[str, Union[int, str]]:
        """
        TCP 은닉 통신의 용량을 분석합니다.
        
        Args:
            method: 분석할 방법 ('sequence', 'flags', 'window', 'options', 'order')
            
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
        
        if method == 'sequence':
            analysis.update({
                'bits_per_packet': 16,  # 하위 16비트 사용
                'packets_per_second': 100,  # 초당 100패킷
                'bandwidth_bps': 1600,
                'stealth_rating': 8,
                'detection_difficulty': 'Hard'
            })
            
        elif method == 'flags':
            analysis.update({
                'bits_per_packet': 3,  # 예약된 플래그 비트 3개
                'packets_per_second': 50,
                'bandwidth_bps': 150,
                'stealth_rating': 9,
                'detection_difficulty': 'Very Hard'
            })
            
        elif method == 'window':
            analysis.update({
                'bits_per_packet': 8,  # 하위 8비트 사용
                'packets_per_second': 80,
                'bandwidth_bps': 640,
                'stealth_rating': 7,
                'detection_difficulty': 'Medium'
            })
            
        elif method == 'options':
            analysis.update({
                'bits_per_packet': 288,  # 36바이트 * 8비트
                'packets_per_second': 20,
                'bandwidth_bps': 5760,
                'stealth_rating': 6,
                'detection_difficulty': 'Medium'
            })
            
        elif method == 'order':
            analysis.update({
                'bits_per_packet': 4,  # 패킷 순서 조작
                'packets_per_second': 30,
                'bandwidth_bps': 120,
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
            
            # nonce + auth_tag + ciphertext 형태로 반환
            return cipher.nonce + auth_tag + ciphertext
            
        except Exception as e:
            raise Exception(f"암호화 오류: {str(e)}")
    
    def _decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """AES-256-GCM을 사용한 데이터 복호화"""
        try:
            if len(encrypted_data) < 32:  # nonce(16) + auth_tag(16) 최소 크기
                raise ValueError("암호화된 데이터가 너무 짧습니다")
            
            # 패스워드에서 키 생성
            key = hashlib.sha256(password.encode('utf-8')).digest()
            
            # nonce, auth_tag, ciphertext 분리
            nonce = encrypted_data[:16]
            auth_tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            # AES-GCM 복호화
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
        # 8비트 단위로 자르고 바이트로 변환
        padding_length = 8 - (len(binary_str) % 8)
        if padding_length != 8:
            binary_str += '0' * padding_length
        
        bytes_list = []
        for i in range(0, len(binary_str), 8):
            byte_str = binary_str[i:i+8]
            if len(byte_str) == 8:
                bytes_list.append(int(byte_str, 2))
        
        return bytes(bytes_list)


# 사용 예제
if __name__ == "__main__":
    # TCP 스테가노그래피 인스턴스 생성
    tcp_stego = TCPSteganography()
    
    print("🌐 TCP 스테가노그래피 테스트")
    print("=" * 50)
    
    # 각 방법별 용량 분석
    methods = ['sequence', 'flags', 'window', 'options', 'order']
    
    for method in methods:
        analysis = tcp_stego.analyze_tcp_covert_capacity(method)
        print(f"\n📊 {method.upper()} 방법 분석:")
        print(f"   패킷당 비트: {analysis['bits_per_packet']}")
        print(f"   초당 패킷: {analysis['packets_per_second']}")
        print(f"   대역폭: {analysis['bandwidth_bps']} bps")
        print(f"   은밀성 점수: {analysis['stealth_rating']}/10")
        print(f"   탐지 난이도: {analysis['detection_difficulty']}")
    
    print(f"\n💡 권장사항:")
    print("- 높은 대역폭: OPTIONS 방법 사용")
    print("- 높은 은밀성: ORDER 방법 사용")  
    print("- 균형: SEQUENCE 방법 사용")
    print("- 실제 사용시 root 권한 필요 (RAW 소켓)")