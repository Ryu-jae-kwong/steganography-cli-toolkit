"""
오디오 스테가노그래피 모듈 v3.0

이 패키지는 오디오 파일을 이용한 다양한 스테가노그래피 기법들을 제공합니다.
- LSB Audio Steganography (기본 LSB 오디오 은닉)
- Echo Hiding (에코 기반 은닉)
- Phase Coding (위상 코딩)
- Spread Spectrum Audio (확산 스펙트럼 오디오)
- Silence Interval Manipulation (무음 구간 조작)

지원 포맷:
- WAV (무손실)
- MP3 (손실 압축)
- FLAC (무손실 압축)
"""

from .lsb_audio import LSBAudioSteganography
from .echo_hiding import EchoHidingSteganography
from .phase_coding import PhaseCodingSteganography
from .silence_manipulation import SilenceManipulationSteganography

__all__ = [
    'LSBAudioSteganography',
    'EchoHidingSteganography',
    'PhaseCodingSteganography',
    'SilenceManipulationSteganography'
]

__version__ = "3.0.0"
__author__ = "디지털포렌식 연구소"