"""
CTF 문제 데이터베이스 v3.0

이 패키지는 실제 CTF 대회에서 출제된 스테가노그래피 문제들과
자체 제작된 교육용 문제들을 체계적으로 분류하고 관리합니다.

구성:
- 실제 CTF 문제 100개 (국제 대회 출처)
- 자체 제작 문제 35개 (교육 및 훈련용)
- 난이도별 분류 (Easy, Medium, Hard, Expert)
- 기법별 분류 (LSB, DCT, DWT, F5, Network 등)
- 자동 해답 검증 시스템
"""

from .problem_manager import CTFProblemManager
from .problem_generator import CTFProblemGenerator
from .difficulty_classifier import DifficultyClassifier

__all__ = [
    'CTFProblemManager',
    'CTFProblemGenerator', 
    'DifficultyClassifier'
]

__version__ = "3.0.0"
__author__ = "디지털포렌식 연구소"