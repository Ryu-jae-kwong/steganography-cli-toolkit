"""
알고리즘 등록 모듈
순환 import 방지를 위한 별도 등록 파일
"""

from .factory import SteganographyFactory, AlgorithmType


def register_all_algorithms():
    """모든 기본 알고리즘을 팩토리에 등록"""
    from .lsb import LSBSteganography
    from .dct import DCTSteganography
    from .dwt import DWTSteganography
    from .f5 import F5Steganography
    
    # 모든 알고리즘 등록
    SteganographyFactory.register_algorithm(AlgorithmType.LSB, LSBSteganography)
    SteganographyFactory.register_algorithm(AlgorithmType.DCT, DCTSteganography)
    SteganographyFactory.register_algorithm(AlgorithmType.DWT, DWTSteganography)
    SteganographyFactory.register_algorithm(AlgorithmType.F5, F5Steganography)