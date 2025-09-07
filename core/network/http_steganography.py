"""
HTTP 스테가노그래피 모듈 v3.0

HTTP 프로토콜을 이용한 스테가노그래피 기법들을 구현합니다.
- HTTP 헤더 조작
- User-Agent 문자열 인코딩
- Cookie 데이터 은닉
- URL 파라미터 조작
- 응답 본문 조작
- Content-Type 조작
"""

import socket
import ssl
import base64
import json
import time
import hashlib
import random
import string
from typing import Optional, Dict, List, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


class HTTPSteganography:
    """HTTP 프로토콜 스테가노그래피 클래스"""
    
    def __init__(self):
        self.session_id = self._generate_session_id()
        
        # HTTP 헤더 조작용 설정
        self.common_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # User-Agent 패턴들
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # 인코딩 방법들
        self.encoding_methods = {
            'base64': self._base64_encode,
            'url': self._url_encode,
            'hex': self._hex_encode,
            'binary': self._binary_encode
        }
        
        self.decoding_methods = {
            'base64': self._base64_decode,
            'url': self._url_decode,
            'hex': self._hex_decode,
            'binary': self._binary_decode
        }
    
    def _generate_session_id(self) -> str:
        """세션 ID 생성"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
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
    
    # 인코딩/디코딩 메서드들
    def _base64_encode(self, data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')
    
    def _base64_decode(self, data: str) -> bytes:
        return base64.b64decode(data)
    
    def _url_encode(self, data: bytes) -> str:
        return quote(data)
    
    def _url_decode(self, data: str) -> bytes:
        return unquote(data).encode('utf-8')
    
    def _hex_encode(self, data: bytes) -> str:
        return data.hex()
    
    def _hex_decode(self, data: str) -> bytes:
        return bytes.fromhex(data)
    
    def _binary_encode(self, data: bytes) -> str:
        return ''.join(format(byte, '08b') for byte in data)
    
    def _binary_decode(self, data: str) -> bytes:
        return bytes(int(data[i:i+8], 2) for i in range(0, len(data), 8))
    
    def embed_in_user_agent(self, data: bytes, encoding: str = 'base64',
                           password: Optional[str] = None) -> str:
        """
        User-Agent 헤더에 데이터를 임베딩합니다.
        
        Args:
            data: 임베딩할 데이터
            encoding: 인코딩 방법 ('base64', 'url', 'hex', 'binary')
            password: 암호화 패스워드
        
        Returns:
            수정된 User-Agent 문자열
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 데이터 인코딩
            encoded_data = self.encoding_methods[encoding](data)
            
            # 기본 User-Agent 선택
            base_ua = random.choice(self.user_agents)
            
            # User-Agent에 데이터 임베딩
            # 버전 번호나 빌드 번호로 위장
            if 'Chrome/' in base_ua:
                # Chrome 버전에 임베딩
                parts = base_ua.split('Chrome/')
                version_part = parts[1].split()[0]
                
                # 인코딩된 데이터를 버전 형태로 변환
                if encoding == 'hex':
                    # 16진수를 점으로 구분된 버전 형태로
                    hex_chunks = [encoded_data[i:i+2] for i in range(0, len(encoded_data), 2)]
                    fake_version = '.'.join([str(int(chunk, 16)) for chunk in hex_chunks[:4]])
                    modified_ua = base_ua.replace(version_part, fake_version + '.' + encoded_data[8:])
                else:
                    # Base64나 다른 형식은 빌드 번호로 위장
                    modified_ua = base_ua.replace('Safari/537.36', f'Safari/537.36.{encoded_data}')
            
            else:
                # 기타 브라우저는 끝에 추가
                modified_ua = f"{base_ua} Build/{encoded_data}"
            
            return modified_ua
            
        except Exception as e:
            print(f"User-Agent 임베딩 오류: {e}")
            return None
    
    def extract_from_user_agent(self, user_agent: str, encoding: str = 'base64',
                               password: Optional[str] = None) -> Optional[bytes]:
        """
        User-Agent 헤더에서 데이터를 추출합니다.
        """
        try:
            # User-Agent에서 인코딩된 데이터 추출
            encoded_data = None
            
            if 'Safari/537.36.' in user_agent:
                # Safari 빌드 번호에서 추출
                parts = user_agent.split('Safari/537.36.')
                if len(parts) > 1:
                    encoded_data = parts[1].split()[0]
            
            elif 'Build/' in user_agent:
                # 빌드 번호에서 추출
                parts = user_agent.split('Build/')
                if len(parts) > 1:
                    encoded_data = parts[1].split()[0]
            
            if not encoded_data:
                return None
            
            # 데이터 디코딩
            data = self.decoding_methods[encoding](encoded_data)
            
            # 데이터 복호화 (필요시)
            if password:
                data = self._decrypt_data(data, password)
            
            return data
            
        except Exception as e:
            print(f"User-Agent 추출 오류: {e}")
            return None
    
    def embed_in_headers(self, data: bytes, headers: Dict[str, str],
                        encoding: str = 'base64', password: Optional[str] = None) -> Dict[str, str]:
        """
        HTTP 헤더들에 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 데이터 인코딩
            encoded_data = self.encoding_methods[encoding](data)
            
            # 데이터를 여러 헤더에 분산
            modified_headers = headers.copy()
            
            # Accept-Language에 가짜 언어 코드로 임베딩
            if 'Accept-Language' in modified_headers:
                lang_data = encoded_data[:16] if len(encoded_data) > 16 else encoded_data
                modified_headers['Accept-Language'] += f',{lang_data};q=0.1'
                encoded_data = encoded_data[16:]
            
            # Accept-Encoding에 가짜 인코딩으로 임베딩
            if encoded_data and 'Accept-Encoding' in modified_headers:
                enc_data = encoded_data[:16] if len(encoded_data) > 16 else encoded_data
                modified_headers['Accept-Encoding'] += f', {enc_data}'
                encoded_data = encoded_data[16:]
            
            # 남은 데이터는 커스텀 헤더에 임베딩
            if encoded_data:
                # X-로 시작하는 커스텀 헤더들
                custom_headers = [
                    'X-Request-ID',
                    'X-Forwarded-For',
                    'X-Real-IP',
                    'X-Session-Token'
                ]
                
                for i, header_name in enumerate(custom_headers):
                    if not encoded_data:
                        break
                    
                    chunk = encoded_data[:32] if len(encoded_data) > 32 else encoded_data
                    modified_headers[header_name] = chunk
                    encoded_data = encoded_data[32:]
            
            return modified_headers
            
        except Exception as e:
            print(f"헤더 임베딩 오류: {e}")
            return headers
    
    def extract_from_headers(self, headers: Dict[str, str], encoding: str = 'base64',
                            password: Optional[str] = None) -> Optional[bytes]:
        """
        HTTP 헤더들에서 데이터를 추출합니다.
        """
        try:
            encoded_parts = []
            
            # Accept-Language에서 추출
            if 'Accept-Language' in headers:
                lang_value = headers['Accept-Language']
                # 가짜 언어 코드 찾기
                parts = lang_value.split(',')
                for part in parts:
                    if ';q=0.1' in part:
                        encoded_parts.append(part.split(';q=0.1')[0].strip())
            
            # Accept-Encoding에서 추출
            if 'Accept-Encoding' in headers:
                enc_value = headers['Accept-Encoding']
                # 표준 인코딩이 아닌 것들 찾기
                standard_encodings = ['gzip', 'deflate', 'br', 'identity']
                parts = enc_value.split(', ')
                for part in parts:
                    part = part.strip()
                    if part not in standard_encodings and part:
                        encoded_parts.append(part)
            
            # 커스텀 헤더에서 추출
            custom_headers = [
                'X-Request-ID',
                'X-Forwarded-For',
                'X-Real-IP',
                'X-Session-Token'
            ]
            
            for header_name in custom_headers:
                if header_name in headers:
                    encoded_parts.append(headers[header_name])
            
            if not encoded_parts:
                return None
            
            # 모든 부분 결합
            encoded_data = ''.join(encoded_parts)
            
            # 데이터 디코딩
            data = self.decoding_methods[encoding](encoded_data)
            
            # 데이터 복호화 (필요시)
            if password:
                data = self._decrypt_data(data, password)
            
            return data
            
        except Exception as e:
            print(f"헤더 추출 오류: {e}")
            return None
    
    def embed_in_cookies(self, data: bytes, cookies: Dict[str, str],
                        encoding: str = 'base64', password: Optional[str] = None) -> Dict[str, str]:
        """
        HTTP 쿠키에 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 데이터 인코딩
            encoded_data = self.encoding_methods[encoding](data)
            
            # 쿠키에 데이터 임베딩
            modified_cookies = cookies.copy()
            
            # 일반적인 쿠키 이름들로 위장
            cookie_names = [
                'session_token',
                'csrf_token',
                'user_pref',
                'lang_setting',
                'theme_mode',
                'last_activity'
            ]
            
            # 데이터를 여러 쿠키에 분산
            chunk_size = len(encoded_data) // len(cookie_names) + 1
            
            for i, cookie_name in enumerate(cookie_names):
                start = i * chunk_size
                end = min((i + 1) * chunk_size, len(encoded_data))
                
                if start < len(encoded_data):
                    chunk = encoded_data[start:end]
                    
                    # 기존 쿠키가 있으면 수정, 없으면 생성
                    if cookie_name in modified_cookies:
                        modified_cookies[cookie_name] = chunk
                    else:
                        modified_cookies[cookie_name] = chunk
            
            return modified_cookies
            
        except Exception as e:
            print(f"쿠키 임베딩 오류: {e}")
            return cookies
    
    def extract_from_cookies(self, cookies: Dict[str, str], encoding: str = 'base64',
                            password: Optional[str] = None) -> Optional[bytes]:
        """
        HTTP 쿠키에서 데이터를 추출합니다.
        """
        try:
            cookie_names = [
                'session_token',
                'csrf_token',
                'user_pref',
                'lang_setting',
                'theme_mode',
                'last_activity'
            ]
            
            encoded_parts = []
            
            # 순서대로 쿠키에서 데이터 추출
            for cookie_name in cookie_names:
                if cookie_name in cookies:
                    encoded_parts.append(cookies[cookie_name])
            
            if not encoded_parts:
                return None
            
            # 모든 부분 결합
            encoded_data = ''.join(encoded_parts)
            
            # 데이터 디코딩
            data = self.decoding_methods[encoding](encoded_data)
            
            # 데이터 복호화 (필요시)
            if password:
                data = self._decrypt_data(data, password)
            
            return data
            
        except Exception as e:
            print(f"쿠키 추출 오류: {e}")
            return None
    
    def embed_in_url_params(self, url: str, data: bytes, encoding: str = 'base64',
                           password: Optional[str] = None) -> str:
        """
        URL 파라미터에 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 데이터 인코딩
            encoded_data = self.encoding_methods[encoding](data)
            
            # URL 파싱
            parsed = urlparse(url)
            params = parse_qs(parsed.query) if parsed.query else {}
            
            # 일반적인 파라미터 이름들로 위장
            param_names = [
                'utm_source',
                'utm_medium',
                'utm_campaign',
                'ref',
                'sid',
                'token'
            ]
            
            # 데이터를 여러 파라미터에 분산
            chunk_size = len(encoded_data) // len(param_names) + 1
            
            for i, param_name in enumerate(param_names):
                start = i * chunk_size
                end = min((i + 1) * chunk_size, len(encoded_data))
                
                if start < len(encoded_data):
                    chunk = encoded_data[start:end]
                    params[param_name] = [chunk]
            
            # URL 재구성
            new_query = urlencode(params, doseq=True)
            modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if new_query:
                modified_url += f"?{new_query}"
            if parsed.fragment:
                modified_url += f"#{parsed.fragment}"
            
            return modified_url
            
        except Exception as e:
            print(f"URL 파라미터 임베딩 오류: {e}")
            return url
    
    def extract_from_url_params(self, url: str, encoding: str = 'base64',
                               password: Optional[str] = None) -> Optional[bytes]:
        """
        URL 파라미터에서 데이터를 추출합니다.
        """
        try:
            # URL 파싱
            parsed = urlparse(url)
            params = parse_qs(parsed.query) if parsed.query else {}
            
            param_names = [
                'utm_source',
                'utm_medium',
                'utm_campaign',
                'ref',
                'sid',
                'token'
            ]
            
            encoded_parts = []
            
            # 순서대로 파라미터에서 데이터 추출
            for param_name in param_names:
                if param_name in params and params[param_name]:
                    encoded_parts.append(params[param_name][0])
            
            if not encoded_parts:
                return None
            
            # 모든 부분 결합
            encoded_data = ''.join(encoded_parts)
            
            # 데이터 디코딩
            data = self.decoding_methods[encoding](encoded_data)
            
            # 데이터 복호화 (필요시)
            if password:
                data = self._decrypt_data(data, password)
            
            return data
            
        except Exception as e:
            print(f"URL 파라미터 추출 오류: {e}")
            return None
    
    def embed_in_response_body(self, response_body: str, data: bytes,
                              encoding: str = 'base64', password: Optional[str] = None) -> str:
        """
        HTTP 응답 본문에 데이터를 임베딩합니다.
        """
        try:
            # 데이터 암호화 (필요시)
            if password:
                data = self._encrypt_data(data, password)
            
            # 데이터 인코딩
            encoded_data = self.encoding_methods[encoding](data)
            
            # HTML 응답인 경우
            if '<html' in response_body.lower():
                # HTML 주석에 임베딩
                comment_data = f'<!-- {encoded_data} -->'
                
                # <head> 태그 뒤에 삽입
                if '<head>' in response_body:
                    response_body = response_body.replace('<head>', f'<head>{comment_data}', 1)
                else:
                    # <html> 태그 뒤에 삽입
                    response_body = response_body.replace('<html>', f'<html>{comment_data}', 1)
            
            # JSON 응답인 경우
            elif response_body.strip().startswith('{'):
                try:
                    json_data = json.loads(response_body)
                    # _metadata 필드에 임베딩
                    json_data['_metadata'] = encoded_data
                    response_body = json.dumps(json_data)
                except:
                    # JSON 파싱 실패시 끝에 추가
                    response_body = response_body.rstrip() + f',\n"_hidden":"{encoded_data}"\n}}'
            
            # 일반 텍스트인 경우
            else:
                # 끝에 숨겨진 텍스트로 추가
                response_body += f'\n<!-- {encoded_data} -->'
            
            return response_body
            
        except Exception as e:
            print(f"응답 본문 임베딩 오류: {e}")
            return response_body
    
    def extract_from_response_body(self, response_body: str, encoding: str = 'base64',
                                  password: Optional[str] = None) -> Optional[bytes]:
        """
        HTTP 응답 본문에서 데이터를 추출합니다.
        """
        try:
            encoded_data = None
            
            # HTML 주석에서 추출
            if '<!--' in response_body and '-->' in response_body:
                import re
                comments = re.findall(r'<!--\s*(.+?)\s*-->', response_body, re.DOTALL)
                for comment in comments:
                    # 인코딩된 데이터인지 확인
                    if len(comment) > 10 and not ' ' in comment:
                        encoded_data = comment.strip()
                        break
            
            # JSON에서 추출
            elif response_body.strip().startswith('{'):
                try:
                    json_data = json.loads(response_body)
                    if '_metadata' in json_data:
                        encoded_data = json_data['_metadata']
                    elif '_hidden' in json_data:
                        encoded_data = json_data['_hidden']
                except:
                    pass
            
            if not encoded_data:
                return None
            
            # 데이터 디코딩
            data = self.decoding_methods[encoding](encoded_data)
            
            # 데이터 복호화 (필요시)
            if password:
                data = self._decrypt_data(data, password)
            
            return data
            
        except Exception as e:
            print(f"응답 본문 추출 오류: {e}")
            return None
    
    def create_covert_request(self, url: str, data: bytes, method: str = 'GET',
                             encoding: str = 'base64', password: Optional[str] = None) -> Dict[str, Any]:
        """
        은밀한 HTTP 요청을 생성합니다.
        """
        try:
            # 기본 헤더 설정
            headers = self.common_headers.copy()
            
            # User-Agent에 데이터 임베딩
            headers['User-Agent'] = self.embed_in_user_agent(data[:100], encoding, password)
            
            # 남은 데이터가 있으면 헤더에 임베딩
            remaining_data = data[100:] if len(data) > 100 else b''
            if remaining_data:
                headers = self.embed_in_headers(remaining_data, headers, encoding, password)
            
            # 쿠키 설정
            cookies = {}
            if len(data) > 200:
                cookie_data = data[200:400] if len(data) > 400 else data[200:]
                cookies = self.embed_in_cookies(cookie_data, cookies, encoding, password)
            
            # URL 파라미터 설정 (GET 요청시)
            modified_url = url
            if method == 'GET' and len(data) > 400:
                url_data = data[400:500] if len(data) > 500 else data[400:]
                modified_url = self.embed_in_url_params(url, url_data, encoding, password)
            
            return {
                'method': method,
                'url': modified_url,
                'headers': headers,
                'cookies': cookies
            }
            
        except Exception as e:
            print(f"은밀한 요청 생성 오류: {e}")
            return None
    
    def analyze_capacity(self, method: str = 'all') -> Dict[str, int]:
        """
        각 HTTP 스테가노그래피 방법의 용량을 분석합니다.
        """
        capacity_info = {}
        
        if method in ['all', 'user_agent']:
            # User-Agent: 보통 200-500 바이트
            ua_capacity = 400  # 바이트
            capacity_info['user_agent'] = ua_capacity
        
        if method in ['all', 'headers']:
            # HTTP 헤더들: Accept-Language (50) + Accept-Encoding (50) + 커스텀 헤더 4개 * 32 = 228 바이트
            headers_capacity = 228
            capacity_info['headers'] = headers_capacity
        
        if method in ['all', 'cookies']:
            # 쿠키들: 6개 쿠키 * 평균 50 바이트 = 300 바이트
            cookies_capacity = 300
            capacity_info['cookies'] = cookies_capacity
        
        if method in ['all', 'url_params']:
            # URL 파라미터: 6개 파라미터 * 평균 30 바이트 = 180 바이트
            url_capacity = 180
            capacity_info['url_params'] = url_capacity
        
        if method in ['all', 'response_body']:
            # 응답 본문: HTML 주석이나 JSON 필드 (제한 없음, 하지만 의심받지 않으려면 1KB 이하)
            response_capacity = 1024
            capacity_info['response_body'] = response_capacity
        
        if method == 'all':
            total_capacity = sum(capacity_info.values())
            capacity_info['total'] = total_capacity
        
        return capacity_info
    
    def get_stealth_rating(self, method: str) -> Dict[str, Any]:
        """
        각 방법의 은밀성 등급을 반환합니다.
        """
        ratings = {
            'user_agent': {
                'stealth': 8,  # 매우 높음
                'capacity': 6,  # 보통
                'detection_risk': 'Low',
                'description': 'User-Agent 문자열은 매우 다양하므로 의심받기 어려움'
            },
            'headers': {
                'stealth': 7,  # 높음
                'capacity': 5,  # 보통-낮음
                'detection_risk': 'Low-Medium',
                'description': 'HTTP 헤더는 일반적이지만 패턴 분석으로 탐지 가능'
            },
            'cookies': {
                'stealth': 6,  # 보통-높음
                'capacity': 6,  # 보통
                'detection_risk': 'Medium',
                'description': '쿠키는 추적되기 쉽지만 내용은 다양함'
            },
            'url_params': {
                'stealth': 5,  # 보통
                'capacity': 4,  # 낮음
                'detection_risk': 'Medium',
                'description': 'URL은 로그에 남기 때문에 추적하기 쉬움'
            },
            'response_body': {
                'stealth': 9,  # 매우 높음
                'capacity': 9,  # 매우 높음
                'detection_risk': 'Very Low',
                'description': '응답 본문은 용량이 크고 다양한 내용이 포함될 수 있음'
            }
        }
        
        return ratings.get(method, {'stealth': 0, 'capacity': 0, 'detection_risk': 'Unknown'})