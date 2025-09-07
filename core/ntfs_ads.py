"""
NTFS Alternative Data Streams (ADS) 분석 모듈

NTFS 파일 시스템에서 사용되는 대체 데이터 스트림을 분석합니다.
Windows에서 파일에 추가 데이터를 숨기는 데 사용됩니다.
"""

import os
import subprocess
import zipfile
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from PIL import Image
import numpy as np

logger = logging.getLogger(__name__)

class NTFSADSAnalyzer:
    """NTFS Alternative Data Streams 분석기"""
    
    def __init__(self):
        self.platform = os.name
        self.supported_platforms = ['nt']  # Windows만 지원
        
    def is_supported(self) -> bool:
        """현재 플랫폼이 NTFS ADS를 지원하는지 확인"""
        return self.platform in self.supported_platforms
    
    def check_ads_streams(self, file_path: str) -> List[Dict[str, Any]]:
        """파일의 ADS 스트림 목록을 반환"""
        if not self.is_supported():
            logger.warning("NTFS ADS는 Windows 플랫폼에서만 지원됩니다")
            return []
        
        streams = []
        
        try:
            # Windows의 DIR 명령으로 ADS 확인
            cmd = f'dir /a /r "{file_path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':' in line and '$DATA' in line:
                        # ADS 스트림 라인 파싱
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            stream_info = {
                                'name': parts[-1],
                                'size': parts[0] if parts[0].isdigit() else 0,
                                'type': 'ADS'
                            }
                            streams.append(stream_info)
                            
        except Exception as e:
            logger.error(f"ADS 검사 중 오류: {e}")
            
        return streams
    
    def extract_ads_content(self, file_path: str, stream_name: str) -> Optional[bytes]:
        """ADS 스트림에서 내용을 추출"""
        if not self.is_supported():
            logger.warning("NTFS ADS는 Windows 플랫폼에서만 지원됩니다")
            return None
            
        try:
            # PowerShell을 사용해서 ADS 내용 읽기
            full_stream_path = f"{file_path}:{stream_name}"
            cmd = f'Get-Content -Path "{full_stream_path}" -Encoding Byte'
            
            result = subprocess.run(['powershell', '-Command', cmd], 
                                  capture_output=True)
            
            if result.returncode == 0:
                return result.stdout
                
        except Exception as e:
            logger.error(f"ADS 내용 추출 중 오류: {e}")
            
        return None
    
    def analyze_zip_as_image(self, zip_path: str) -> Dict[str, Any]:
        """ZIP 파일을 이미지로 변환한 케이스 분석"""
        analysis_result = {
            'zip_info': {},
            'image_conversion': {},
            'hidden_data': {},
            'reconstruction_possible': False
        }
        
        try:
            # ZIP 파일 기본 정보
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                zip_size = os.path.getsize(zip_path)
                
                analysis_result['zip_info'] = {
                    'file_count': len(file_list),
                    'file_list': file_list,
                    'total_size': zip_size,
                    'compressed_size': sum(info.compress_size for info in zip_ref.infolist())
                }
                
                # 각 파일의 메타데이터 확인
                for info in zip_ref.infolist():
                    if hasattr(info, 'extra') and info.extra:
                        analysis_result['hidden_data'][info.filename] = {
                            'extra_data': info.extra,
                            'extra_size': len(info.extra)
                        }
                        
        except Exception as e:
            logger.error(f"ZIP 분석 중 오류: {e}")
            
        return analysis_result
    
    def convert_zip_to_image(self, zip_path: str, output_path: str, 
                           method: str = 'rgb') -> bool:
        """ZIP 파일을 이미지로 변환"""
        try:
            with open(zip_path, 'rb') as f:
                zip_data = f.read()
            
            if method == 'rgb':
                # RGB 방식: 3바이트씩 RGB 픽셀로 변환
                pixels_needed = len(zip_data) // 3
                if len(zip_data) % 3 != 0:
                    # 패딩 추가
                    zip_data += b'\x00' * (3 - (len(zip_data) % 3))
                    pixels_needed += 1
                
                # 정사각형에 가까운 크기 계산
                width = int(pixels_needed ** 0.5) + 1
                height = (pixels_needed // width) + 1
                
                # 이미지 데이터 생성
                img_data = np.zeros((height, width, 3), dtype=np.uint8)
                
                idx = 0
                for i in range(height):
                    for j in range(width):
                        if idx + 2 < len(zip_data):
                            img_data[i, j] = [zip_data[idx], 
                                            zip_data[idx + 1], 
                                            zip_data[idx + 2]]
                            idx += 3
                
                # 이미지 저장
                img = Image.fromarray(img_data, 'RGB')
                img.save(output_path)
                
            elif method == 'grayscale':
                # 그레이스케일 방식: 1바이트씩 픽셀로 변환
                pixels_needed = len(zip_data)
                width = int(pixels_needed ** 0.5) + 1
                height = (pixels_needed // width) + 1
                
                img_data = np.zeros((height, width), dtype=np.uint8)
                
                idx = 0
                for i in range(height):
                    for j in range(width):
                        if idx < len(zip_data):
                            img_data[i, j] = zip_data[idx]
                            idx += 1
                
                img = Image.fromarray(img_data, 'L')
                img.save(output_path)
                
            return True
            
        except Exception as e:
            logger.error(f"ZIP를 이미지로 변환 중 오류: {e}")
            return False
    
    def reconstruct_zip_from_image(self, image_path: str, output_path: str,
                                 original_size: Optional[int] = None) -> bool:
        """이미지에서 ZIP 파일을 복원"""
        try:
            img = Image.open(image_path)
            
            if img.mode == 'RGB':
                # RGB 이미지에서 복원
                img_array = np.array(img)
                zip_bytes = bytearray()
                
                for i in range(img_array.shape[0]):
                    for j in range(img_array.shape[1]):
                        r, g, b = img_array[i, j]
                        zip_bytes.extend([r, g, b])
                        
            elif img.mode == 'L':
                # 그레이스케일 이미지에서 복원
                img_array = np.array(img)
                zip_bytes = bytearray()
                
                for i in range(img_array.shape[0]):
                    for j in range(img_array.shape[1]):
                        zip_bytes.append(img_array[i, j])
            
            # 원본 크기가 주어진 경우 자르기
            if original_size and original_size < len(zip_bytes):
                zip_bytes = zip_bytes[:original_size]
            
            # ZIP 파일로 저장
            with open(output_path, 'wb') as f:
                f.write(zip_bytes)
            
            # ZIP 파일 유효성 검사
            try:
                with zipfile.ZipFile(output_path, 'r') as zip_ref:
                    zip_ref.testzip()
                return True
            except:
                # ZIP 헤더 찾기 시도
                zip_header = b'PK\x03\x04'
                header_pos = zip_bytes.find(zip_header)
                if header_pos != -1:
                    # 헤더부터 시작하는 데이터만 저장
                    with open(output_path, 'wb') as f:
                        f.write(zip_bytes[header_pos:])
                    return True
                
                return False
                
        except Exception as e:
            logger.error(f"이미지에서 ZIP 복원 중 오류: {e}")
            return False
    
    def find_hidden_flags(self, zip_path: str) -> List[str]:
        """ZIP 파일에서 숨겨진 플래그 찾기"""
        flags = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    # 파일 이름에서 플래그 검색
                    import re
                    flag_pattern = r'flag\{[^}]+\}'
                    
                    # 파일명에서 플래그 찾기
                    matches = re.findall(flag_pattern, file_info.filename, re.IGNORECASE)
                    flags.extend(matches)
                    
                    # 파일 내용에서 플래그 찾기
                    try:
                        file_content = zip_ref.read(file_info).decode('utf-8', errors='ignore')
                        content_matches = re.findall(flag_pattern, file_content, re.IGNORECASE)
                        flags.extend(content_matches)
                    except:
                        # 바이너리 파일인 경우 바이트 패턴으로 검색
                        try:
                            file_bytes = zip_ref.read(file_info)
                            # 바이트에서 텍스트 플래그 찾기
                            text_parts = re.findall(b'flag\\{[^}]+\\}', file_bytes, re.IGNORECASE)
                            for part in text_parts:
                                try:
                                    flags.append(part.decode('utf-8'))
                                except:
                                    pass
                        except:
                            pass
                    
                    # 파일의 extra data에서 플래그 찾기
                    if hasattr(file_info, 'extra') and file_info.extra:
                        try:
                            extra_text = file_info.extra.decode('utf-8', errors='ignore')
                            extra_matches = re.findall(flag_pattern, extra_text, re.IGNORECASE)
                            flags.extend(extra_matches)
                        except:
                            pass
                            
        except Exception as e:
            logger.error(f"플래그 검색 중 오류: {e}")
            
        return list(set(flags))  # 중복 제거
    
    def cross_platform_ads_simulation(self, file_path: str) -> Dict[str, Any]:
        """크로스 플랫폼 ADS 시뮬레이션 (macOS/Linux에서 테스트용)"""
        result = {
            'simulated': True,
            'platform': self.platform,
            'ads_streams': [],
            'hidden_content': {}
        }
        
        # 파일 확장 속성 확인 (macOS의 경우)
        if self.platform == 'posix':
            try:
                # xattr 명령 사용 (macOS)
                cmd = ['xattr', '-l', file_path]
                proc_result = subprocess.run(cmd, capture_output=True, text=True)
                
                if proc_result.returncode == 0:
                    lines = proc_result.stdout.strip().split('\n')
                    for line in lines:
                        if ':' in line:
                            attr_name, attr_value = line.split(':', 1)
                            result['ads_streams'].append({
                                'name': attr_name.strip(),
                                'value': attr_value.strip(),
                                'type': 'xattr'
                            })
            except Exception as e:
                logger.debug(f"xattr 검사 실패: {e}")
        
        return result