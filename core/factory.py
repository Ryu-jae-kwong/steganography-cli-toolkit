"""
스테가노그래피 알고리즘 팩토리
Stegano 라이브러리와 OpenStego 패턴 참조
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Type, Protocol
from pathlib import Path
from PIL import Image

from .exceptions import AlgorithmNotSupportedError


class AlgorithmType(Enum):
    """지원되는 스테가노그래피 알고리즘"""
    LSB = "lsb"
    DCT = "dct"
    DWT = "dwt"
    F5 = "f5"


class SteganographyAlgorithm(Protocol):
    """스테가노그래피 알고리즘 인터페이스"""
    
    def embed_message(self, image_path: str, message: str, output_path: str, **kwargs) -> bool:
        """메시지를 이미지에 임베딩"""
        ...
    
    def extract_message(self, image_path: str, **kwargs) -> str:
        """이미지에서 메시지 추출"""
        ...
    
    def get_capacity(self, image_path: str) -> int:
        """이미지의 최대 저장 가능 용량"""
        ...
    
    def check_message_presence(self, image_path: str) -> bool:
        """메시지 존재 여부 확인"""
        ...


class SteganographyFactory:
    """
    알고리즘 팩토리 클래스
    다양한 스테가노그래피 알고리즘을 통일된 인터페이스로 제공
    """
    
    _algorithms: Dict[AlgorithmType, Type] = {}
    
    @classmethod
    def register_algorithm(cls, algorithm_type: AlgorithmType, algorithm_class: Type):
        """새로운 알고리즘 등록"""
        cls._algorithms[algorithm_type] = algorithm_class
    
    @classmethod
    def create_algorithm(cls, algorithm_type: AlgorithmType) -> SteganographyAlgorithm:
        """알고리즘 타입에 따른 구현체 생성"""
        if algorithm_type not in cls._algorithms:
            raise AlgorithmNotSupportedError(algorithm_type.value)
        
        algorithm_class = cls._algorithms[algorithm_type]
        return algorithm_class()
    
    @classmethod
    def get_supported_algorithms(cls) -> list[AlgorithmType]:
        """지원되는 알고리즘 목록 반환"""
        return list(cls._algorithms.keys())
    
    @classmethod
    def list_algorithms(cls) -> Dict[str, str]:
        """알고리즘 목록을 사람이 읽기 쉬운 형태로 반환"""
        descriptions = {
            AlgorithmType.LSB: "LSB (Least Significant Bit) - 기본적이고 빠른 알고리즘",
            AlgorithmType.DCT: "DCT (Discrete Cosine Transform) - JPEG 호환 알고리즘", 
            AlgorithmType.DWT: "DWT (Discrete Wavelet Transform) - 고급 주파수 도메인",
            AlgorithmType.F5: "F5 - 고급 JPEG 스테가노그래피"
        }
        
        result = {}
        for algorithm_type in cls._algorithms:
            result[algorithm_type.value] = descriptions.get(algorithm_type, "설명 없음")
        
        return result


