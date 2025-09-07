"""
비디오 스테가노그래피 모듈 v3.0

이 패키지는 비디오 파일을 이용한 다양한 스테가노그래피 기법들을 제공합니다.
- LSB Video Steganography (기본 LSB 비디오 은닉)
- Frame Injection (프레임 삽입)
- DCT Video Steganography (DCT 비디오 은닉)
- Motion Vector Steganography (모션 벡터 조작)
- Inter-frame Correlation (프레임 간 상관관계 이용)

지원 포맷:
- AVI (무압축/압축)
- MP4 (H.264/H.265)
- MOV (QuickTime)
- MKV (Matroska)
"""

from .lsb_video import LSBVideoSteganography
from .frame_injection import FrameInjectionSteganography
from .dct_video import DCTVideoSteganography
from .motion_vector import MotionVectorSteganography

__all__ = [
    'LSBVideoSteganography',
    'FrameInjectionSteganography',
    'DCTVideoSteganography',
    'MotionVectorSteganography'
]

__version__ = "3.0.0"
__author__ = "디지털포렌식 연구소"