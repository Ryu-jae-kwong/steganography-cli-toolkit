"""
스테가노그래피 예외 클래스 정의
Rust와 Java 오픈소스 패턴 기반 에러 처리
"""

from typing import Optional


class SteganographyError(Exception):
    """스테가노그래피 기본 예외 클래스"""
    
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class InvalidImageError(SteganographyError):
    """잘못된 이미지 파일 예외"""
    
    def __init__(self, image_path: str, reason: str = ""):
        message = f"잘못된 이미지 파일: {image_path}"
        if reason:
            message += f" - {reason}"
        super().__init__(message, "INVALID_IMAGE")


class MessageTooLargeError(SteganographyError):
    """메시지가 이미지 용량을 초과하는 경우"""
    
    def __init__(self, required: int, capacity: int):
        message = f"메시지가 너무 큽니다. 필요: {required} 바이트, 용량: {capacity} 바이트"
        super().__init__(message, "MESSAGE_TOO_LARGE")
        self.required = required
        self.capacity = capacity


class ExtractionError(SteganographyError):
    """메시지 추출 실패"""
    
    def __init__(self, reason: str = "구분자를 찾을 수 없습니다"):
        super().__init__(f"메시지 추출 실패: {reason}", "EXTRACTION_FAILED")


class CryptographyError(SteganographyError):
    """암호화/복호화 관련 오류"""
    
    def __init__(self, operation: str, reason: str = ""):
        message = f"암호화 오류 ({operation})"
        if reason:
            message += f": {reason}"
        super().__init__(message, "CRYPTO_ERROR")


class AlgorithmNotSupportedError(SteganographyError):
    """지원되지 않는 알고리즘"""
    
    def __init__(self, algorithm: str):
        super().__init__(f"지원되지 않는 알고리즘: {algorithm}", "UNSUPPORTED_ALGORITHM")