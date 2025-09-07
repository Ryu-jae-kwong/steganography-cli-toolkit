"""
텍스트 스테가노그래피 모듈 v3.0

이 모듈은 다양한 텍스트 기반 스테가노그래피 기법들을 구현합니다:
- Unicode 제로폭 문자 활용
- 공백 패턴 조작
- 문자 치환 암호화
- 줄바꿈 패턴 조작
- 단어 간격 조작
- 문장 부호 조작

지원 포맷: TXT, RTF, HTML, Markdown
"""

import os
import re
import unicodedata
from typing import List, Tuple, Dict, Optional, Union
import base64
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib


class TextSteganography:
    """
    텍스트 스테가노그래피 클래스
    
    다양한 텍스트 기반 은닉 기법을 제공합니다.
    """
    
    def __init__(self):
        """클래스 초기화"""
        self.supported_formats = ['.txt', '.rtf', '.html', '.htm', '.md', '.markdown']
        
        # 제로폭 문자들 (Zero-width characters)
        self.zero_width_chars = {
            'ZWSP': '\u200B',    # Zero Width Space
            'ZWNJ': '\u200C',    # Zero Width Non-Joiner
            'ZWJ': '\u200D',     # Zero Width Joiner
            'ZWNBSP': '\uFEFF',  # Zero Width No-Break Space
            'LRM': '\u200E',     # Left-to-Right Mark
            'RLM': '\u200F',     # Right-to-Left Mark
        }
        
        # 유사한 문자들 (Homoglyphs)
        self.homoglyphs = {
            'a': ['а', 'ａ', 'α'],  # Latin a, Cyrillic a, Fullwidth a, Greek alpha
            'e': ['е', 'ｅ'],        # Latin e, Cyrillic e, Fullwidth e
            'o': ['о', 'ｏ', 'ο'],  # Latin o, Cyrillic o, Fullwidth o, Greek omicron
            'p': ['р', 'ｐ', 'ρ'],  # Latin p, Cyrillic p, Fullwidth p, Greek rho
            'i': ['і', 'ｉ', 'ι'],  # Latin i, Cyrillic i, Fullwidth i, Greek iota
            'c': ['с', 'ｃ'],        # Latin c, Cyrillic c, Fullwidth c
            'n': ['п', 'ｎ'],        # Latin n, Cyrillic n, Fullwidth n
            'x': ['х', 'ｘ', 'χ'],  # Latin x, Cyrillic x, Fullwidth x, Greek chi
            's': ['ѕ', 'ｓ'],        # Latin s, Cyrillic s, Fullwidth s
            'y': ['у', 'ｙ'],        # Latin y, Cyrillic y, Fullwidth y
        }
        
        # 공백 문자들
        self.space_chars = {
            'SPACE': ' ',           # Regular space
            'NBSP': '\u00A0',       # Non-breaking space
            'THIN_SPACE': '\u2009', # Thin space
            'HAIR_SPACE': '\u200A', # Hair space
            'EN_SPACE': '\u2002',   # En space
            'EM_SPACE': '\u2003',   # Em space
        }
        
    def embed_message(self, text_path: str, message: str, output_path: str, 
                     method: str = 'zero_width', password: Optional[str] = None) -> bool:
        """
        텍스트에 메시지를 임베딩합니다.
        
        Args:
            text_path: 원본 텍스트 파일 경로
            message: 숨길 메시지
            output_path: 출력 파일 경로
            method: 임베딩 방법 ('zero_width', 'space_pattern', 'homoglyph', 'line_pattern')
            password: 암호화 패스워드 (선택사항)
            
        Returns:
            bool: 성공 시 True, 실패 시 False
        """
        try:
            if not os.path.exists(text_path):
                raise FileNotFoundError(f"입력 파일을 찾을 수 없습니다: {text_path}")
            
            # 원본 텍스트 로드
            with open(text_path, 'r', encoding='utf-8') as f:
                original_text = f.read()
            
            if not original_text.strip():
                raise ValueError("입력 텍스트가 비어있습니다")
            
            # 데이터 암호화 (패스워드가 제공된 경우)
            data_to_embed = message.encode('utf-8')
            if password:
                data_to_embed = self._encrypt_data(data_to_embed, password)
            
            # 바이너리로 변환
            binary_data = self._bytes_to_binary(data_to_embed)
            
            # 방법에 따라 임베딩
            if method == 'zero_width':
                stego_text = self._embed_zero_width(original_text, binary_data)
            elif method == 'space_pattern':
                stego_text = self._embed_space_pattern(original_text, binary_data)
            elif method == 'homoglyph':
                stego_text = self._embed_homoglyph(original_text, binary_data)
            elif method == 'line_pattern':
                stego_text = self._embed_line_pattern(original_text, binary_data)
            else:
                raise ValueError(f"지원하지 않는 방법입니다: {method}")
            
            if not stego_text:
                raise ValueError("임베딩에 실패했습니다")
            
            # 결과 저장
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(stego_text)
            
            return True
            
        except Exception as e:
            print(f"텍스트 임베딩 중 오류 발생: {str(e)}")
            return False
    
    def extract_message(self, stego_path: str, method: str = 'zero_width',
                       password: Optional[str] = None) -> Optional[str]:
        """
        텍스트에서 메시지를 추출합니다.
        
        Args:
            stego_path: 스테고 텍스트 파일 경로
            method: 추출 방법
            password: 복호화 패스워드 (선택사항)
            
        Returns:
            str: 추출된 메시지 또는 None
        """
        try:
            if not os.path.exists(stego_path):
                raise FileNotFoundError(f"스테고 파일을 찾을 수 없습니다: {stego_path}")
            
            # 스테고 텍스트 로드
            with open(stego_path, 'r', encoding='utf-8') as f:
                stego_text = f.read()
            
            # 방법에 따라 추출
            if method == 'zero_width':
                binary_data = self._extract_zero_width(stego_text)
            elif method == 'space_pattern':
                binary_data = self._extract_space_pattern(stego_text)
            elif method == 'homoglyph':
                binary_data = self._extract_homoglyph(stego_text)
            elif method == 'line_pattern':
                binary_data = self._extract_line_pattern(stego_text)
            else:
                raise ValueError(f"지원하지 않는 방법입니다: {method}")
            
            if not binary_data:
                return None
            
            # 바이너리에서 바이트로 변환
            data_bytes = self._binary_to_bytes(binary_data)
            
            # 데이터 복호화 (패스워드가 제공된 경우)
            if password:
                data_bytes = self._decrypt_data(data_bytes, password)
            
            return data_bytes.decode('utf-8', errors='ignore')
            
        except Exception as e:
            print(f"텍스트 추출 중 오류 발생: {str(e)}")
            return None
    
    def _embed_zero_width(self, text: str, binary_data: str) -> str:
        """제로폭 문자를 이용한 데이터 임베딩"""
        if len(binary_data) == 0:
            return text
        
        # 단어 사이에 제로폭 문자 삽입
        words = text.split()
        if len(words) < len(binary_data):
            # 데이터가 너무 크면 문자 사이에도 삽입
            result = ""
            bit_index = 0
            
            for char in text:
                result += char
                if bit_index < len(binary_data) and char.isalpha():
                    if binary_data[bit_index] == '1':
                        result += self.zero_width_chars['ZWSP']
                    else:
                        result += self.zero_width_chars['ZWNJ']
                    bit_index += 1
            
            return result
        else:
            # 단어 사이에 삽입
            result = []
            for i, word in enumerate(words):
                result.append(word)
                if i < len(binary_data):
                    if binary_data[i] == '1':
                        if i < len(words) - 1:  # 마지막 단어가 아닌 경우
                            result.append(self.zero_width_chars['ZWSP'])
                    else:
                        if i < len(words) - 1:
                            result.append(self.zero_width_chars['ZWNJ'])
                
                if i < len(words) - 1:
                    result.append(' ')
            
            return ''.join(result)
    
    def _extract_zero_width(self, stego_text: str) -> str:
        """제로폭 문자에서 데이터 추출"""
        binary_data = ""
        
        for char in stego_text:
            if char == self.zero_width_chars['ZWSP']:
                binary_data += '1'
            elif char == self.zero_width_chars['ZWNJ']:
                binary_data += '0'
        
        return binary_data
    
    def _embed_space_pattern(self, text: str, binary_data: str) -> str:
        """공백 패턴을 이용한 데이터 임베딩"""
        if len(binary_data) == 0:
            return text
        
        # 공백을 다른 공백 문자로 교체
        result = ""
        bit_index = 0
        
        for char in text:
            if char == ' ' and bit_index < len(binary_data):
                if binary_data[bit_index] == '1':
                    result += self.space_chars['NBSP']  # Non-breaking space for 1
                else:
                    result += self.space_chars['SPACE']  # Regular space for 0
                bit_index += 1
            else:
                result += char
        
        return result
    
    def _extract_space_pattern(self, stego_text: str) -> str:
        """공백 패턴에서 데이터 추출"""
        binary_data = ""
        
        for char in stego_text:
            if char == self.space_chars['NBSP']:
                binary_data += '1'
            elif char == ' ':
                binary_data += '0'
        
        return binary_data
    
    def _embed_homoglyph(self, text: str, binary_data: str) -> str:
        """동형 문자를 이용한 데이터 임베딩"""
        if len(binary_data) == 0:
            return text
        
        result = ""
        bit_index = 0
        
        for char in text:
            if char.lower() in self.homoglyphs and bit_index < len(binary_data):
                if binary_data[bit_index] == '1':
                    # 동형 문자로 교체
                    homoglyph_chars = self.homoglyphs[char.lower()]
                    replacement = random.choice(homoglyph_chars)
                    result += replacement if char.islower() else replacement.upper()
                else:
                    result += char  # 원본 문자 유지
                bit_index += 1
            else:
                result += char
        
        return result
    
    def _extract_homoglyph(self, stego_text: str) -> str:
        """동형 문자에서 데이터 추출"""
        binary_data = ""
        
        for char in stego_text:
            char_lower = char.lower()
            found_homoglyph = False
            
            # 동형 문자인지 확인
            for original_char, homoglyph_list in self.homoglyphs.items():
                if char_lower in homoglyph_list and char_lower != original_char:
                    binary_data += '1'
                    found_homoglyph = True
                    break
                elif char_lower == original_char:
                    # 다른 동형 문자가 사용될 수 있는 위치에서 원본 문자 사용 = 0
                    if any(char_lower in homoglyphs for homoglyphs in self.homoglyphs.values()):
                        binary_data += '0'
                        found_homoglyph = True
                        break
        
        return binary_data
    
    def _embed_line_pattern(self, text: str, binary_data: str) -> str:
        """줄바꿈 패턴을 이용한 데이터 임베딩"""
        if len(binary_data) == 0:
            return text
        
        lines = text.split('\n')
        result = []
        bit_index = 0
        
        for line in lines:
            result.append(line)
            
            if bit_index < len(binary_data):
                if binary_data[bit_index] == '1':
                    # 줄 끝에 공백 추가
                    result[-1] += ' '
                # 0인 경우는 그대로 유지
                bit_index += 1
        
        return '\n'.join(result)
    
    def _extract_line_pattern(self, stego_text: str) -> str:
        """줄바꿈 패턴에서 데이터 추출"""
        binary_data = ""
        lines = stego_text.split('\n')
        
        for line in lines:
            if line.endswith(' '):
                binary_data += '1'
            else:
                binary_data += '0'
        
        return binary_data
    
    def get_capacity(self, text_path: str, method: str = 'zero_width') -> int:
        """
        텍스트 파일의 은닉 용량을 계산합니다.
        
        Args:
            text_path: 텍스트 파일 경로
            method: 임베딩 방법
            
        Returns:
            int: 최대 은닉 가능 바이트 수
        """
        try:
            if not os.path.exists(text_path):
                return 0
            
            with open(text_path, 'r', encoding='utf-8') as f:
                text = f.read()
            
            if method == 'zero_width':
                # 문자 수 기반 (각 문자 사이에 1비트)
                char_count = len([c for c in text if c.isalpha()])
                return char_count // 8  # 비트를 바이트로 변환
                
            elif method == 'space_pattern':
                # 공백 수 기반
                space_count = text.count(' ')
                return space_count // 8
                
            elif method == 'homoglyph':
                # 동형 문자 가능한 문자 수
                homoglyph_count = sum(1 for c in text if c.lower() in self.homoglyphs)
                return homoglyph_count // 8
                
            elif method == 'line_pattern':
                # 줄 수 기반
                line_count = len(text.split('\n'))
                return line_count // 8
                
            else:
                return 0
                
        except Exception as e:
            print(f"용량 계산 중 오류 발생: {str(e)}")
            return 0
    
    def analyze_suitability(self, text_path: str) -> Dict[str, Union[str, int, float]]:
        """
        텍스트 파일의 스테가노그래피 적합성을 분석합니다.
        
        Args:
            text_path: 텍스트 파일 경로
            
        Returns:
            dict: 분석 결과
        """
        try:
            if not os.path.exists(text_path):
                return {'error': '파일을 찾을 수 없습니다'}
            
            with open(text_path, 'r', encoding='utf-8') as f:
                text = f.read()
            
            analysis = {
                'file_size': len(text.encode('utf-8')),
                'character_count': len(text),
                'word_count': len(text.split()),
                'line_count': len(text.split('\n')),
                'space_count': text.count(' '),
                'alphabet_count': len([c for c in text if c.isalpha()]),
                'homoglyph_opportunities': sum(1 for c in text if c.lower() in self.homoglyphs),
                'unicode_chars': len([c for c in text if ord(c) > 127]),
                'methods': {}
            }
            
            # 각 방법별 용량 및 적합성 평가
            methods = ['zero_width', 'space_pattern', 'homoglyph', 'line_pattern']
            
            for method in methods:
                capacity = self.get_capacity(text_path, method)
                
                if method == 'zero_width':
                    suitability = min(100, analysis['alphabet_count'] / 10)
                elif method == 'space_pattern':
                    suitability = min(100, analysis['space_count'] / 5)
                elif method == 'homoglyph':
                    suitability = min(100, analysis['homoglyph_opportunities'] / 3)
                elif method == 'line_pattern':
                    suitability = min(100, analysis['line_count'] / 2)
                else:
                    suitability = 0
                
                analysis['methods'][method] = {
                    'capacity_bytes': capacity,
                    'capacity_chars': capacity * 8,  # 최대 문자 수 (1문자 = 1비트 가정)
                    'suitability_score': round(suitability, 2)
                }
            
            # 전체 적합성 점수
            avg_suitability = sum(method['suitability_score'] 
                                for method in analysis['methods'].values()) / len(methods)
            analysis['overall_suitability'] = round(avg_suitability, 2)
            
            # 추천 방법
            best_method = max(analysis['methods'].items(), 
                            key=lambda x: x[1]['suitability_score'])
            analysis['recommended_method'] = best_method[0]
            
            return analysis
            
        except Exception as e:
            return {'error': f'분석 중 오류 발생: {str(e)}'}
    
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
    
    def is_suitable_file(self, file_path: str) -> bool:
        """
        파일이 텍스트 스테가노그래피에 적합한지 확인합니다.
        
        Args:
            file_path: 파일 경로
            
        Returns:
            bool: 적합하면 True, 부적합하면 False
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            # 파일 확장자 확인
            _, ext = os.path.splitext(file_path.lower())
            if ext not in self.supported_formats:
                return False
            
            # 파일 크기 확인 (10MB 이하)
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return False
            
            # 텍스트 내용 확인
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read(1000)  # 처음 1000자만 확인
            
            # 최소 텍스트 길이 확인
            if len(text.strip()) < 100:
                return False
            
            # 바이너리 파일인지 확인
            if '\x00' in text:
                return False
            
            return True
            
        except Exception:
            return False


# 사용 예제
if __name__ == "__main__":
    # 텍스트 스테가노그래피 인스턴스 생성
    text_stego = TextSteganography()
    
    # 테스트용 텍스트 파일 생성
    test_text = """
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. 
    Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. 
    Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris 
    nisi ut aliquip ex ea commodo consequat. 
    
    Duis aute irure dolor in reprehenderit in voluptate velit esse 
    cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat 
    cupidatat non proident, sunt in culpa qui officia deserunt mollit 
    anim id est laborum.
    """
    
    # 테스트 실행 예제
    test_file = "test_text.txt"
    stego_file = "stego_text.txt"
    secret_message = "This is a secret message hidden in text!"
    
    # 파일 생성
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_text)
    
    print("📝 텍스트 스테가노그래피 테스트")
    print("=" * 50)
    
    # 파일 적합성 분석
    analysis = text_stego.analyze_suitability(test_file)
    print(f"📊 분석 결과: {analysis}")
    
    # 메시지 임베딩 (제로폭 문자 방법)
    print(f"\n🔒 메시지 임베딩: '{secret_message}'")
    success = text_stego.embed_message(test_file, secret_message, stego_file, 
                                     method='zero_width', password='test123')
    
    if success:
        print("✅ 임베딩 성공!")
        
        # 메시지 추출
        extracted = text_stego.extract_message(stego_file, method='zero_width', 
                                             password='test123')
        print(f"🔓 추출된 메시지: '{extracted}'")
        
        if extracted == secret_message:
            print("🎉 테스트 성공! 메시지가 완전히 복원되었습니다.")
        else:
            print("❌ 테스트 실패: 메시지가 일치하지 않습니다.")
    else:
        print("❌ 임베딩 실패")
    
    # 정리
    import os
    if os.path.exists(test_file):
        os.remove(test_file)
    if os.path.exists(stego_file):
        os.remove(stego_file)