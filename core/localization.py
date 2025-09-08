"""
Localization Manager for Steganography Tool v5.0
Provides multi-language support for English and Korean
"""

from typing import Dict, Any

class LocalizationManager:
    """Manages multi-language text resources"""
    
    def __init__(self):
        self.current_language = 'en'
        self.messages = {
            'en': {
                # Header messages
                'analysis_header': 'STEGANOGRAPHY ANALYSIS',
                'file_info': 'FILE INFORMATION',
                'algorithm_results': 'ALGORITHM RESULTS',
                'summary': 'SUMMARY',
                'batch_analysis': 'BATCH ANALYSIS',
                'archive_analysis': 'ARCHIVE ANALYSIS',
                
                # File information
                'file': 'File',
                'size': 'Size',
                'type': 'Type',
                'pixels': 'pixels',
                'time': 'Time',
                'hash_md5': 'MD5',
                'hash_sha1': 'SHA-1',
                'hash_sha256': 'SHA-256',
                
                # Algorithm status
                'found': 'FOUND',
                'weak': 'WEAK',
                'none': 'NONE',
                'error': 'ERROR',
                'success': 'SUCCESS',
                'warning': 'WARNING',
                'failed': 'FAILED',
                
                # Analysis results
                'algorithm': 'Algorithm',
                'status': 'Status',
                'data_found': 'Data Found',
                'confidence': 'Confidence',
                'extracted_data': 'Extracted Data',
                'data_size': 'Size',
                'data_type': 'Type',
                
                # Summary messages
                'steganography_detected': 'STEGANOGRAPHY DETECTED',
                'no_steganography': 'NO STEGANOGRAPHY DETECTED',
                'algorithms_detected': 'algorithms detected steganography',
                'total_extracted': 'total extracted',
                'bytes': 'bytes',
                'verdict_positive': 'POSITIVE - Multiple methods detected',
                'verdict_suspicious': 'SUSPICIOUS - Weak signals detected',
                'verdict_clean': 'CLEAN - No steganography found',
                
                # Data types
                'text_data': 'Text message',
                'binary_data': 'Binary data',
                'image_data': 'Embedded image',
                'document_data': 'Document file',
                'archive_data': 'Archive file',
                'unknown_data': 'Unknown format',
                
                # Algorithm names
                'lsb_analysis': 'LSB Analysis',
                'dct_analysis': 'DCT Analysis',
                'dwt_analysis': 'DWT Analysis',
                'f5_analysis': 'F5 Analysis',
                'metadata_analysis': 'Metadata Analysis',
                'statistical_analysis': 'Statistical Analysis',
                'bpcs_analysis': 'BPCS Analysis',
                'alpha_analysis': 'Alpha Channel Analysis',
                'jsteg_analysis': 'JSteg Detection',
                'pvd_analysis': 'PVD Analysis',
                'histogram_analysis': 'Histogram Analysis',
                
                # Batch processing messages
                'total_files': 'Total files',
                'files_with_steganography': 'Files with steganography',
                'archive': 'Archive',
                'files_in_archive': 'Files in archive',
                
                # Error messages
                'file_not_found': 'File not found',
                'analysis_error': 'Analysis error',
                'invalid_format': 'Invalid file format',
                'processing_error': 'Processing error'
            },
            'ko': {
                # Header messages
                'analysis_header': '스테가노그래피 분석',
                'file_info': '파일 정보',
                'algorithm_results': '알고리즘 분석 결과',
                'summary': '분석 요약',
                'batch_analysis': '배치 분석',
                'archive_analysis': '압축 파일 분석',
                
                # File information
                'file': '파일',
                'size': '크기',
                'type': '형식',
                'pixels': '픽셀',
                'time': '시간',
                'hash_md5': 'MD5',
                'hash_sha1': 'SHA-1',
                'hash_sha256': 'SHA-256',
                
                # Algorithm status
                'found': '발견됨',
                'weak': '약한신호',
                'none': '없음',
                'error': '오류',
                'success': '성공',
                'warning': '경고',
                'failed': '실패',
                
                # Analysis results
                'algorithm': '알고리즘',
                'status': '상태',
                'data_found': '발견된 데이터',
                'confidence': '신뢰도',
                'extracted_data': '추출된 데이터',
                'data_size': '크기',
                'data_type': '유형',
                
                # Summary messages
                'steganography_detected': '스테가노그래피 탐지됨',
                'no_steganography': '스테가노그래피 탐지 안됨',
                'algorithms_detected': '개 알고리즘에서 스테가노그래피 탐지',
                'total_extracted': '총 추출량',
                'bytes': '바이트',
                'verdict_positive': '양성 - 다중 기법 탐지',
                'verdict_suspicious': '의심 - 약한 신호 탐지',
                'verdict_clean': '정상 - 스테가노그래피 없음',
                
                # Data types
                'text_data': '텍스트 메시지',
                'binary_data': '바이너리 데이터',
                'image_data': '임베디드 이미지',
                'document_data': '문서 파일',
                'archive_data': '압축 파일',
                'unknown_data': '알 수 없는 형식',
                
                # Algorithm names
                'lsb_analysis': 'LSB 분석',
                'dct_analysis': 'DCT 분석',
                'dwt_analysis': 'DWT 분석',
                'f5_analysis': 'F5 분석',
                'metadata_analysis': '메타데이터 분석',
                'statistical_analysis': '통계 분석',
                'bpcs_analysis': 'BPCS 분석',
                'alpha_analysis': '알파 채널 분석',
                'jsteg_analysis': 'JSteg 탐지',
                'pvd_analysis': 'PVD 분석',
                'histogram_analysis': '히스토그램 분석',
                
                # Batch processing messages
                'total_files': '전체 파일',
                'files_with_steganography': '스테가노그래피 발견된 파일',
                'archive': '압축 파일',
                'files_in_archive': '압축 파일 내 파일',
                
                # Error messages
                'file_not_found': '파일을 찾을 수 없음',
                'analysis_error': '분석 오류',
                'invalid_format': '잘못된 파일 형식',
                'processing_error': '처리 오류'
            }
        }
    
    def set_language(self, language: str) -> None:
        """Set the current language"""
        if language in self.messages:
            self.current_language = language
        else:
            self.current_language = 'en'
    
    def get(self, key: str, **kwargs) -> str:
        """Get localized message by key"""
        message = self.messages[self.current_language].get(key, key)
        
        # Simple string formatting support
        if kwargs:
            try:
                return message.format(**kwargs)
            except (KeyError, ValueError):
                return message
        
        return message
    
    def get_language(self) -> str:
        """Get current language"""
        return self.current_language