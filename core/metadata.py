"""
메타데이터 분석 모듈 (v2.0 신규)
PNG, JPEG 파일의 메타데이터에서 숨겨진 정보를 추출합니다.

주요 기능:
- PNG 청크 분석 (zTXt, tEXt, iTXt)
- EXIF 데이터 추출
- 압축된 메타데이터 해제
- CTF 문제: Hit a Brick Wall 해결
"""

import struct
import zlib
import base64
from typing import Dict, List, Optional, Any, Tuple
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
import re


class MetadataAnalyzer:
    """메타데이터 분석 클래스"""
    
    def __init__(self):
        self.supported_formats = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """파일의 모든 메타데이터를 분석"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")
        
        file_ext = os.path.splitext(file_path)[1].lower()
        
        results = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'format': file_ext,
            'metadata': {},
            'hidden_data': [],
            'suspicious_patterns': []
        }
        
        if file_ext == '.png':
            results.update(self.analyze_png(file_path))
        elif file_ext in ['.jpg', '.jpeg']:
            results.update(self.analyze_jpeg(file_path))
        else:
            results.update(self.analyze_generic_exif(file_path))
            
        return results
    
    def analyze_png(self, file_path: str) -> Dict[str, Any]:
        """PNG 파일의 청크 구조를 분석"""
        print(f"🔍 PNG 파일 분석 중: {file_path}")
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # PNG 시그니처 확인
        if data[:8] != b'\x89PNG\r\n\x1a\n':
            raise ValueError("유효한 PNG 파일이 아닙니다")
        
        chunks = self._parse_png_chunks(data)
        metadata = {}
        hidden_data = []
        suspicious = []
        
        # 각 청크 타입별 처리
        for chunk in chunks:
            chunk_type = chunk['type']
            chunk_data = chunk['data']
            
            if chunk_type == 'zTXt':
                # 압축된 텍스트 청크 (Hit a Brick Wall 해결!)
                result = self._process_ztxt_chunk(chunk_data)
                metadata['zTXt'] = result
                if result.get('decompressed_data'):
                    hidden_data.append({
                        'source': 'zTXt chunk',
                        'data': result['decompressed_data'],
                        'compressed': True
                    })
                    suspicious.append("zTXt 청크에서 압축된 데이터 발견")
            
            elif chunk_type == 'tEXt':
                # 일반 텍스트 청크
                result = self._process_text_chunk(chunk_data)
                metadata['tEXt'] = result
                if result.get('value'):
                    hidden_data.append({
                        'source': 'tEXt chunk',
                        'data': result['value'],
                        'compressed': False
                    })
            
            elif chunk_type == 'iTXt':
                # 국제화 텍스트 청크
                result = self._process_itext_chunk(chunk_data)
                metadata['iTXt'] = result
                if result.get('text'):
                    hidden_data.append({
                        'source': 'iTXt chunk',
                        'data': result['text'],
                        'compressed': result.get('compressed', False)
                    })
            
            elif chunk_type in ['IHDR', 'PLTE', 'IDAT', 'IEND']:
                # 필수 청크들
                metadata[chunk_type] = self._process_standard_chunk(chunk_type, chunk_data)
            
            else:
                # 기타 보조 청크들
                metadata[chunk_type] = {
                    'size': len(chunk_data),
                    'raw_data': chunk_data[:100].hex() if len(chunk_data) > 100 else chunk_data.hex()
                }
                if chunk_type not in ['bKGD', 'cHRM', 'gAMA', 'hIST', 'pHYs', 'sBIT', 'tIME', 'tRNS']:
                    suspicious.append(f"비표준 청크 발견: {chunk_type}")
        
        return {
            'png_chunks': chunks,
            'metadata': metadata,
            'hidden_data': hidden_data,
            'suspicious_patterns': suspicious
        }
    
    def _parse_png_chunks(self, data: bytes) -> List[Dict[str, Any]]:
        """PNG 청크 구조 파싱"""
        chunks = []
        pos = 8  # PNG 시그니처 건너뛰기
        
        while pos < len(data):
            if pos + 8 > len(data):
                break
                
            # 길이 (4바이트)
            length = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            
            # 타입 (4바이트)
            chunk_type = data[pos:pos+4].decode('ascii', errors='ignore')
            pos += 4
            
            # 데이터
            chunk_data = data[pos:pos+length] if length > 0 else b''
            pos += length
            
            # CRC (4바이트)
            crc = struct.unpack('>I', data[pos:pos+4])[0] if pos + 4 <= len(data) else 0
            pos += 4
            
            chunks.append({
                'type': chunk_type,
                'length': length,
                'data': chunk_data,
                'crc': crc
            })
            
            # IEND 청크에서 종료
            if chunk_type == 'IEND':
                break
        
        return chunks
    
    def _process_ztxt_chunk(self, data: bytes) -> Dict[str, Any]:
        """zTXt 청크 처리 (압축된 텍스트) - Hit a Brick Wall 핵심!"""
        try:
            # zTXt 형식: keyword\0compression_method + compressed_text
            null_pos = data.find(b'\x00')
            if null_pos == -1:
                return {'error': 'null 구분자를 찾을 수 없음'}
            
            keyword = data[:null_pos].decode('latin1')
            
            # 압축 방법 (1바이트)
            if null_pos + 1 >= len(data):
                return {'error': '압축 방법 바이트 없음'}
            
            compression_method = data[null_pos + 1]
            compressed_data = data[null_pos + 2:]
            
            # zlib 압축 해제
            if compression_method == 0:  # zlib 압축
                try:
                    decompressed = zlib.decompress(compressed_data)
                    decompressed_text = decompressed.decode('utf-8', errors='ignore')
                    
                    return {
                        'keyword': keyword,
                        'compression_method': compression_method,
                        'compressed_size': len(compressed_data),
                        'decompressed_size': len(decompressed),
                        'decompressed_data': decompressed_text,
                        'raw_decompressed': decompressed
                    }
                except Exception as e:
                    return {
                        'keyword': keyword,
                        'compression_method': compression_method,
                        'error': f'압축 해제 실패: {str(e)}',
                        'raw_compressed': compressed_data[:100].hex()
                    }
            else:
                return {
                    'keyword': keyword,
                    'compression_method': compression_method,
                    'error': f'지원하지 않는 압축 방법: {compression_method}'
                }
        
        except Exception as e:
            return {'error': f'zTXt 처리 오류: {str(e)}'}
    
    def _process_text_chunk(self, data: bytes) -> Dict[str, Any]:
        """tEXt 청크 처리 (일반 텍스트)"""
        try:
            null_pos = data.find(b'\x00')
            if null_pos == -1:
                return {'error': 'null 구분자를 찾을 수 없음'}
            
            keyword = data[:null_pos].decode('latin1')
            value = data[null_pos + 1:].decode('latin1', errors='ignore')
            
            return {
                'keyword': keyword,
                'value': value
            }
        except Exception as e:
            return {'error': f'tEXt 처리 오류: {str(e)}'}
    
    def _process_itext_chunk(self, data: bytes) -> Dict[str, Any]:
        """iTXt 청크 처리 (국제화 텍스트)"""
        try:
            # iTXt 형식: keyword\0compression_flag\0compression_method\0language_tag\0translated_keyword\0text
            parts = data.split(b'\x00', 4)
            if len(parts) < 5:
                return {'error': 'iTXt 형식이 올바르지 않음'}
            
            keyword = parts[0].decode('utf-8', errors='ignore')
            compression_flag = parts[1][0] if len(parts[1]) > 0 else 0
            compression_method = parts[2][0] if len(parts[2]) > 0 else 0
            language_tag = parts[3].decode('utf-8', errors='ignore')
            translated_keyword = parts[4].decode('utf-8', errors='ignore')
            
            # 나머지는 텍스트 데이터
            text_data = data[len(parts[0]) + len(parts[1]) + len(parts[2]) + len(parts[3]) + len(parts[4]) + 5:]
            
            if compression_flag == 1 and compression_method == 0:
                # 압축된 텍스트
                try:
                    text = zlib.decompress(text_data).decode('utf-8', errors='ignore')
                except:
                    text = text_data.decode('utf-8', errors='ignore')
            else:
                text = text_data.decode('utf-8', errors='ignore')
            
            return {
                'keyword': keyword,
                'compression_flag': compression_flag,
                'compression_method': compression_method,
                'language_tag': language_tag,
                'translated_keyword': translated_keyword,
                'text': text,
                'compressed': compression_flag == 1
            }
        except Exception as e:
            return {'error': f'iTXt 처리 오류: {str(e)}'}
    
    def _process_standard_chunk(self, chunk_type: str, data: bytes) -> Dict[str, Any]:
        """표준 PNG 청크 처리"""
        if chunk_type == 'IHDR':
            # 이미지 헤더
            if len(data) >= 13:
                width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack('>IIBBBBB', data)
                return {
                    'width': width,
                    'height': height,
                    'bit_depth': bit_depth,
                    'color_type': color_type,
                    'compression': compression,
                    'filter_method': filter_method,
                    'interlace': interlace
                }
        elif chunk_type == 'IDAT':
            # 이미지 데이터
            return {
                'size': len(data),
                'compressed_image_data': True
            }
        elif chunk_type == 'IEND':
            # 파일 끝
            return {'end_of_file': True}
        
        return {
            'size': len(data),
            'raw_data': data[:50].hex() if len(data) > 50 else data.hex()
        }
    
    def search_for_flags(self, analysis_result: Dict[str, Any]) -> List[str]:
        """분석 결과에서 CTF 플래그 패턴 검색"""
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}', 
            r'CTF\{[^}]+\}',
            r'ctf\{[^}]+\}'
        ]
        
        # 숨겨진 데이터에서 검색
        for hidden in analysis_result.get('hidden_data', []):
            data = str(hidden.get('data', ''))
            for pattern in flag_patterns:
                matches = re.findall(pattern, data, re.IGNORECASE)
                flags.extend(matches)
        
        # 메타데이터에서 검색
        def search_in_dict(d):
            if isinstance(d, dict):
                for v in d.values():
                    search_in_dict(v)
            elif isinstance(d, str):
                for pattern in flag_patterns:
                    matches = re.findall(pattern, d, re.IGNORECASE)
                    flags.extend(matches)
            elif isinstance(d, list):
                for item in d:
                    search_in_dict(item)
        
        search_in_dict(analysis_result.get('metadata', {}))
        
        return list(set(flags))  # 중복 제거


def main():
    """메타데이터 분석 도구 테스트"""
    analyzer = MetadataAnalyzer()
    
    # Hit a Brick Wall CTF 문제 테스트
    test_file = "CTF-문제-사진/hit_a_brick_wall/bricks.png"
    
    if os.path.exists(test_file):
        print("🎯 Hit a Brick Wall CTF 문제 분석 시작")
        print("=" * 60)
        
        result = analyzer.analyze_file(test_file)
        
        # 결과 출력
        print(f"📁 파일: {result['file_path']}")
        print(f"📊 크기: {result['file_size']:,} 바이트")
        print(f"🎨 형식: {result['format']}")
        print()
        
        # 숨겨진 데이터
        if result['hidden_data']:
            print("🔍 발견된 숨겨진 데이터:")
            for i, data in enumerate(result['hidden_data'], 1):
                print(f"  {i}. 출처: {data['source']}")
                print(f"     데이터: {data['data'][:200]}...")
                print()
        
        # 플래그 검색
        flags = analyzer.search_for_flags(result)
        if flags:
            print("🚩 발견된 플래그:")
            for flag in flags:
                print(f"  ✅ {flag}")
        else:
            print("❌ 플래그를 찾을 수 없습니다")
        
        print("\n" + "=" * 60)
    else:
        print("❌ 테스트 파일을 찾을 수 없습니다")


if __name__ == "__main__":
    main()