"""
스테가노그래피 브루트포스 모듈
stegbrute (R4yGM) 패턴 기반 Python 구현
"""

import time
from pathlib import Path
from typing import Optional, List, Tuple, Generator
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .lsb import LSBSteganography
from .factory import AlgorithmType, SteganographyFactory
from .exceptions import SteganographyError


class SteganographyBruteForcer:
    """
    스테가노그래피 브루트포스 공격 클래스
    stegbrute 패턴을 Python으로 이식
    """
    
    def __init__(self):
        self.wordlists = []
        self.algorithms = [AlgorithmType.LSB]  # 확장 가능
        self.found_passwords = []
    
    def load_wordlist(self, wordlist_path: str) -> int:
        """
        패스워드 리스트 로드
        
        Args:
            wordlist_path: 워드리스트 파일 경로
            
        Returns:
            로드된 패스워드 개수
        """
        try:
            path = Path(wordlist_path)
            if not path.exists():
                raise FileNotFoundError(f"워드리스트 파일이 없습니다: {wordlist_path}")
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            self.wordlists.extend(passwords)
            return len(passwords)
            
        except Exception as e:
            raise SteganographyError(f"워드리스트 로드 실패: {e}")
    
    def generate_common_passwords(self, count: int = 1000) -> Generator[str, None, None]:
        """
        일반적인 패스워드 패턴 생성
        stegbrute의 패턴 생성 방식 참조
        """
        # 기본 패스워드들 (먼저 yield)
        common = [
            "123456", "password", "admin", "root", "guest", "user",
            "test", "demo", "temp", "default", "qwerty", "abc123",
            "12345", "1234", "123", "pass", "secret", "hidden"
        ]
        
        for pwd in common:
            yield pwd
        
        # 숫자 조합
        for num in range(1000):
            yield str(num)
            yield f"{num:04d}"
        
        # 기본 단어 + 숫자 조합
        for base in ["password", "admin", "test", "pass", "secret", "key"]:
            for num in range(1000):
                yield f"{base}{num}"
                if num < 100:
                    yield f"{base}{num:02d}"
                    yield f"{base}{num:03d}"
        
        # 년도 조합  
        for year in range(2020, 2026):
            yield str(year)
            yield f"password{year}"
            yield f"admin{year}"
    
    def brute_force_attack(self, image_path: str, 
                          algorithm: AlgorithmType = AlgorithmType.LSB,
                          max_attempts: int = 1000) -> Optional[Tuple[str, str]]:
        """
        브루트포스 공격 실행
        
        Args:
            image_path: 대상 이미지 경로
            algorithm: 사용할 알고리즘
            max_attempts: 최대 시도 횟수
            
        Returns:
            (패스워드, 메시지) 튜플 또는 None
        """
        try:
            # 알고리즘 생성
            stego_algorithm = SteganographyFactory.create_algorithm(algorithm)
            
            # 패스워드 리스트 준비
            password_candidates = list(self.wordlists)
            
            # 일반적인 패스워드 추가
            password_candidates.extend(list(self.generate_common_passwords(500)))
            
            # 중복 제거하되 순서 유지
            seen = set()
            unique_passwords = []
            for pwd in password_candidates:
                if pwd not in seen:
                    seen.add(pwd)
                    unique_passwords.append(pwd)
            
            password_candidates = unique_passwords[:max_attempts]
            
            print(f"🚀 브루트포스 공격 시작...")
            print(f"📊 총 {len(password_candidates)}개 패스워드 시도")
            print(f"🔍 첫 10개 패스워드: {password_candidates[:10]}")
            
            # Progress bar로 시각적 피드백
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                
                task = progress.add_task("패스워드 시도 중...", total=len(password_candidates))
                
                for i, password in enumerate(password_candidates):
                    try:
                        # 추출 시도
                        extracted_message = stego_algorithm.extract_message(
                            image_path, password=password
                        )
                        
                        # 성공적으로 추출된 경우
                        if extracted_message and len(extracted_message.strip()) > 0:
                            progress.stop()
                            result = (password, extracted_message)
                            self.found_passwords.append(result)
                            
                            print(f"✅ 패스워드 발견!")
                            print(f"🔑 패스워드: {password}")
                            print(f"💬 메시지: {extracted_message}")
                            
                            return result
                            
                    except Exception as e:
                        # 디버깅을 위해 특정 패스워드에서 에러 확인
                        if password == "123456":
                            print(f"🔍 디버깅: 패스워드 '123456' 시도 중 오류: {e}")
                        pass
                    
                    # 진행률 업데이트
                    if i % 100 == 0:
                        progress.update(task, advance=100)
                    elif i == len(password_candidates) - 1:
                        progress.update(task, advance=len(password_candidates) % 100)
            
            print("❌ 유효한 패스워드를 찾지 못했습니다")
            return None
            
        except Exception as e:
            raise SteganographyError(f"브루트포스 공격 실패: {e}")
    
    def quick_check(self, image_path: str) -> bool:
        """
        빠른 메시지 존재 확인
        패스워드 없이 메시지가 있는지 확인
        """
        try:
            stego_algorithm = SteganographyFactory.create_algorithm(AlgorithmType.LSB)
            return stego_algorithm.check_message_presence(image_path)
        except:
            return False
    
    def analyze_image(self, image_path: str) -> dict:
        """
        이미지 분석 정보 반환
        """
        try:
            stego_algorithm = SteganographyFactory.create_algorithm(AlgorithmType.LSB)
            
            from PIL import Image
            image = Image.open(image_path)
            width, height = image.size
            
            return {
                "path": image_path,
                "size": f"{width}x{height}",
                "mode": image.mode,
                "capacity": stego_algorithm.get_capacity(image_path),
                "has_message": self.quick_check(image_path),
                "algorithms_to_try": len(self.algorithms)
            }
            
        except Exception as e:
            return {"error": str(e)}