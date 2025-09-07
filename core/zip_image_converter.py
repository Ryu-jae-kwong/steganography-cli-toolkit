"""
ZIP-to-Image 변환 분석 모듈

ZIP 파일과 이미지 간의 변환 및 분석을 담당합니다.
디지털 포렌식에서 데이터 은닉 기법 중 하나인 파일 형식 변환을 다룹니다.
"""

import os
import zipfile
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from PIL import Image
import numpy as np
import struct

logger = logging.getLogger(__name__)

class ZipImageConverter:
    """ZIP 파일과 이미지 간 변환 분석기"""
    
    def __init__(self):
        self.supported_formats = ['PNG', 'BMP', 'TIFF', 'JPEG']
        
    def analyze_image_for_zip(self, image_path: str) -> Dict[str, Any]:
        """이미지에 ZIP 데이터가 숨겨져 있는지 분석"""
        result = {
            'has_zip_signature': False,
            'zip_signatures': [],
            'potential_zip_data': False,
            'image_info': {},
            'analysis': {}
        }
        
        try:
            # 이미지 기본 정보
            img = Image.open(image_path)
            result['image_info'] = {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'file_size': os.path.getsize(image_path)
            }
            
            # 이미지 데이터를 바이트로 변환
            img_array = np.array(img)
            
            if img.mode == 'RGB':
                # RGB 이미지의 경우
                flat_data = img_array.flatten()
                byte_data = flat_data.astype(np.uint8).tobytes()
            elif img.mode == 'L':
                # 그레이스케일 이미지의 경우
                byte_data = img_array.astype(np.uint8).tobytes()
            else:
                logger.warning(f"지원하지 않는 이미지 모드: {img.mode}")
                return result
            
            # ZIP 시그니처 검색
            zip_signatures = [
                (b'PK\x03\x04', 'ZIP Local File Header'),
                (b'PK\x01\x02', 'ZIP Central Directory Header'),
                (b'PK\x05\x06', 'ZIP End of Central Directory'),
                (b'PK\x07\x08', 'ZIP Data Descriptor')
            ]
            
            for signature, description in zip_signatures:
                positions = self._find_all_occurrences(byte_data, signature)
                if positions:
                    result['has_zip_signature'] = True
                    result['zip_signatures'].append({
                        'signature': signature.hex(),
                        'description': description,
                        'positions': positions[:10]  # 처음 10개만
                    })
            
            # ZIP 데이터 추출 시도
            if result['has_zip_signature']:
                extracted_zip = self._extract_zip_from_bytes(byte_data)
                if extracted_zip:
                    result['potential_zip_data'] = True
                    result['analysis'] = self._analyze_extracted_zip(extracted_zip)
                    
        except Exception as e:
            logger.error(f"이미지 분석 중 오류: {e}")
            result['error'] = str(e)
            
        return result
    
    def convert_zip_to_rgb_image(self, zip_path: str, output_path: str) -> bool:
        """ZIP 파일을 RGB 이미지로 변환"""
        try:
            with open(zip_path, 'rb') as f:
                zip_data = f.read()
            
            # 3의 배수로 맞추기 위해 패딩 추가
            padding_needed = (3 - (len(zip_data) % 3)) % 3
            if padding_needed > 0:
                zip_data += b'\x00' * padding_needed
            
            # RGB 픽셀 수 계산
            pixel_count = len(zip_data) // 3
            
            # 정사각형에 가까운 크기 계산
            width = int(pixel_count ** 0.5) + 1
            height = (pixel_count // width) + 1
            
            # 이미지 배열 생성
            img_array = np.zeros((height, width, 3), dtype=np.uint8)
            
            # ZIP 데이터를 RGB 픽셀로 변환
            for i in range(0, len(zip_data), 3):
                pixel_idx = i // 3
                row = pixel_idx // width
                col = pixel_idx % width
                
                if row < height and col < width:
                    img_array[row, col] = [
                        zip_data[i],
                        zip_data[i + 1] if i + 1 < len(zip_data) else 0,
                        zip_data[i + 2] if i + 2 < len(zip_data) else 0
                    ]
            
            # 이미지 저장
            img = Image.fromarray(img_array, 'RGB')
            img.save(output_path)
            
            logger.info(f"ZIP을 RGB 이미지로 변환 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"ZIP to RGB 변환 중 오류: {e}")
            return False
    
    def convert_zip_to_grayscale_image(self, zip_path: str, output_path: str) -> bool:
        """ZIP 파일을 그레이스케일 이미지로 변환"""
        try:
            with open(zip_path, 'rb') as f:
                zip_data = f.read()
            
            # 픽셀 수는 바이트 수와 같음
            pixel_count = len(zip_data)
            
            # 정사각형에 가까운 크기 계산
            width = int(pixel_count ** 0.5) + 1
            height = (pixel_count // width) + 1
            
            # 이미지 배열 생성
            img_array = np.zeros((height, width), dtype=np.uint8)
            
            # ZIP 데이터를 그레이스케일 픽셀로 변환
            for i, byte_val in enumerate(zip_data):
                row = i // width
                col = i % width
                
                if row < height and col < width:
                    img_array[row, col] = byte_val
            
            # 이미지 저장
            img = Image.fromarray(img_array, 'L')
            img.save(output_path)
            
            logger.info(f"ZIP을 그레이스케일 이미지로 변환 완료: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"ZIP to 그레이스케일 변환 중 오류: {e}")
            return False
    
    def reconstruct_zip_from_rgb_image(self, image_path: str, output_path: str,
                                     original_size: Optional[int] = None) -> bool:
        """RGB 이미지에서 ZIP 파일 복원"""
        try:
            img = Image.open(image_path)
            
            if img.mode != 'RGB':
                logger.error("RGB 이미지가 아닙니다")
                return False
            
            img_array = np.array(img)
            zip_bytes = bytearray()
            
            # RGB 픽셀을 바이트로 변환
            for row in range(img_array.shape[0]):
                for col in range(img_array.shape[1]):
                    r, g, b = img_array[row, col]
                    zip_bytes.extend([r, g, b])
            
            # 원본 크기로 자르기 (알고 있는 경우)
            if original_size and len(zip_bytes) > original_size:
                zip_bytes = zip_bytes[:original_size]
            
            # ZIP 헤더 찾기
            zip_header = b'PK\x03\x04'
            header_pos = zip_bytes.find(zip_header)
            
            if header_pos == -1:
                logger.error("ZIP 헤더를 찾을 수 없습니다")
                return False
            
            # 헤더부터 시작하는 데이터 저장
            zip_data = zip_bytes[header_pos:]
            
            # ZIP 끝부분 찾기 시도
            end_signature = b'PK\x05\x06'
            end_pos = zip_data.rfind(end_signature)
            if end_pos != -1:
                # ZIP 끝부분까지만 저장
                zip_data = zip_data[:end_pos + 22]  # ZIP End Record는 최소 22바이트
            
            with open(output_path, 'wb') as f:
                f.write(zip_data)
            
            # ZIP 파일 유효성 검사
            try:
                with zipfile.ZipFile(output_path, 'r') as zip_ref:
                    zip_ref.testzip()
                logger.info(f"ZIP 파일 복원 완료: {output_path}")
                return True
            except zipfile.BadZipFile:
                logger.error("복원된 ZIP 파일이 손상되었습니다")
                return False
                
        except Exception as e:
            logger.error(f"RGB 이미지에서 ZIP 복원 중 오류: {e}")
            return False
    
    def find_flags_in_zip(self, zip_path: str) -> List[str]:
        """ZIP 파일에서 플래그 찾기"""
        flags = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # 파일 목록에서 플래그 찾기
                for file_name in zip_ref.namelist():
                    flags.extend(self._extract_flags_from_text(file_name))
                
                # 각 파일 내용에서 플래그 찾기
                for file_info in zip_ref.infolist():
                    try:
                        file_content = zip_ref.read(file_info)
                        
                        # 텍스트 파일 처리
                        try:
                            text_content = file_content.decode('utf-8', errors='ignore')
                            flags.extend(self._extract_flags_from_text(text_content))
                        except:
                            pass
                        
                        # 바이너리에서 플래그 패턴 찾기
                        flags.extend(self._extract_flags_from_binary(file_content))
                        
                    except Exception as file_error:
                        logger.debug(f"파일 {file_info.filename} 처리 중 오류: {file_error}")
                        continue
                        
        except Exception as e:
            logger.error(f"ZIP에서 플래그 검색 중 오류: {e}")
            
        return list(set(flags))  # 중복 제거
    
    def _find_all_occurrences(self, data: bytes, pattern: bytes) -> List[int]:
        """데이터에서 패턴의 모든 위치 찾기"""
        positions = []
        start = 0
        
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
            
        return positions
    
    def _extract_zip_from_bytes(self, data: bytes) -> Optional[bytes]:
        """바이트 데이터에서 ZIP 추출"""
        zip_header = b'PK\x03\x04'
        header_pos = data.find(zip_header)
        
        if header_pos == -1:
            return None
        
        # ZIP 끝부분 찾기
        end_signature = b'PK\x05\x06'
        end_pos = data.rfind(end_signature)
        
        if end_pos != -1:
            return data[header_pos:end_pos + 22]
        else:
            # 끝부분을 찾을 수 없으면 헤더부터 끝까지
            return data[header_pos:]
    
    def _analyze_extracted_zip(self, zip_data: bytes) -> Dict[str, Any]:
        """추출된 ZIP 데이터 분석"""
        analysis = {
            'valid_zip': False,
            'file_count': 0,
            'file_list': [],
            'flags_found': []
        }
        
        try:
            # 임시 파일로 저장 후 분석
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
                temp_file.write(zip_data)
                temp_path = temp_file.name
            
            try:
                with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                    analysis['valid_zip'] = True
                    analysis['file_list'] = zip_ref.namelist()
                    analysis['file_count'] = len(analysis['file_list'])
                    analysis['flags_found'] = self.find_flags_in_zip(temp_path)
                    
            except zipfile.BadZipFile:
                analysis['valid_zip'] = False
            finally:
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"ZIP 분석 중 오류: {e}")
            
        return analysis
    
    def _extract_flags_from_text(self, text: str) -> List[str]:
        """텍스트에서 플래그 추출"""
        import re
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[a-zA-Z0-9_!@#$%^&*()+=\-.,<>?/|\\:;"\'\[\]]+\}'
        ]
        
        flags = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
            
        return flags
    
    def _extract_flags_from_binary(self, data: bytes) -> List[str]:
        """바이너리 데이터에서 플래그 추출"""
        flags = []
        
        try:
            # 바이너리에서 텍스트 부분 추출
            text_parts = []
            current_text = bytearray()
            
            for byte in data:
                if 32 <= byte <= 126:  # 출력 가능한 ASCII
                    current_text.append(byte)
                else:
                    if len(current_text) > 5:  # 최소 5글자 이상
                        text_parts.append(current_text.decode('ascii'))
                    current_text = bytearray()
            
            # 마지막 텍스트 부분 처리
            if len(current_text) > 5:
                text_parts.append(current_text.decode('ascii'))
            
            # 각 텍스트 부분에서 플래그 찾기
            for text in text_parts:
                flags.extend(self._extract_flags_from_text(text))
                
        except Exception as e:
            logger.debug(f"바이너리에서 플래그 추출 중 오류: {e}")
            
        return flags
    
    def analyze_zip_structure(self, zip_path: str) -> Dict[str, Any]:
        """ZIP 파일 구조 분석"""
        result = {
            'file_count': 0,
            'file_list': [],
            'total_uncompressed_size': 0,
            'total_compressed_size': 0,
            'compression_ratio': 0.0,
            'extra_data_info': []
        }
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_infos = zip_ref.infolist()
                result['file_count'] = len(file_infos)
                
                for file_info in file_infos:
                    result['file_list'].append(file_info.filename)
                    result['total_uncompressed_size'] += file_info.file_size
                    result['total_compressed_size'] += file_info.compress_size
                    
                    if file_info.extra:
                        result['extra_data_info'].append({
                            'filename': file_info.filename,
                            'extra_size': len(file_info.extra),
                            'extra_data': file_info.extra.hex()
                        })
                
                if result['total_uncompressed_size'] > 0:
                    result['compression_ratio'] = 1 - (result['total_compressed_size'] / result['total_uncompressed_size'])
                    
        except Exception as e:
            logger.error(f"ZIP 구조 분석 중 오류: {e}")
            result['error'] = str(e)
            
        return result
    
    def reconstruct_zip_from_grayscale_image(self, image_path: str, output_path: str,
                                           original_size: Optional[int] = None) -> bool:
        """그레이스케일 이미지에서 ZIP 파일 복원"""
        try:
            img = Image.open(image_path)
            
            if img.mode != 'L':
                logger.error("그레이스케일 이미지가 아닙니다")
                return False
            
            img_array = np.array(img)
            zip_bytes = bytearray()
            
            # 그레이스케일 픽셀을 바이트로 변환
            for row in range(img_array.shape[0]):
                for col in range(img_array.shape[1]):
                    zip_bytes.append(img_array[row, col])
            
            # 원본 크기로 자르기 (알고 있는 경우)
            if original_size and len(zip_bytes) > original_size:
                zip_bytes = zip_bytes[:original_size]
            
            # ZIP 헤더 찾기
            zip_header = b'PK\x03\x04'
            header_pos = zip_bytes.find(zip_header)
            
            if header_pos == -1:
                logger.error("ZIP 헤더를 찾을 수 없습니다")
                return False
            
            # 헤더부터 시작하는 데이터 저장
            zip_data = zip_bytes[header_pos:]
            
            # ZIP 끝부분 찾기 시도
            end_signature = b'PK\x05\x06'
            end_pos = zip_data.rfind(end_signature)
            if end_pos != -1:
                # ZIP 끝부분까지만 저장
                zip_data = zip_data[:end_pos + 22]  # ZIP End Record는 최소 22바이트
            
            with open(output_path, 'wb') as f:
                f.write(zip_data)
            
            # ZIP 파일 유효성 검사
            try:
                with zipfile.ZipFile(output_path, 'r') as zip_ref:
                    zip_ref.testzip()
                logger.info(f"그레이스케일 이미지에서 ZIP 파일 복원 완료: {output_path}")
                return True
            except zipfile.BadZipFile:
                logger.error("복원된 ZIP 파일이 손상되었습니다")
                return False
                
        except Exception as e:
            logger.error(f"그레이스케일 이미지에서 ZIP 복원 중 오류: {e}")
            return False