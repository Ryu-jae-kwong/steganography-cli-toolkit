"""
문서 스테가노그래피 모듈 v3.0

이 패키지는 다양한 문서 파일 형식을 이용한 스테가노그래피 기법들을 제공합니다.
- PDF Document Steganography (PDF 메타데이터 및 구조 조작)
- Word Document Steganography (DOCX 텍스트 속성 조작)
- Text Format Steganography (Unicode 및 공백 문자 조작)
- Excel Steganography (셀 속성 및 숨김 데이터)

지원 포맷:
- PDF (Portable Document Format)
- DOCX (Microsoft Word 문서)
- TXT (일반 텍스트)
- XLSX (Microsoft Excel)
- RTF (Rich Text Format)
"""

from .pdf_steganography import PDFSteganography
from .docx_steganography import DOCXSteganography
from .text_steganography import TextSteganography

__all__ = [
    'PDFSteganography',
    'DOCXSteganography', 
    'TextSteganography'
]

__version__ = "3.0.0"
__author__ = "디지털포렌식 연구소"