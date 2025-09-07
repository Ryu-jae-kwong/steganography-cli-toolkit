"""
난이도 분류기 v3.0

CTF 문제의 난이도를 자동으로 분류하는 AI 기반 시스템입니다.
문제의 복잡도, 필요한 기술, 소요 시간 등을 종합적으로 분석하여
Easy, Medium, Hard, Expert 4단계로 분류합니다.
"""

import re
import math
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class Difficulty(Enum):
    EASY = "Easy"
    MEDIUM = "Medium"
    HARD = "Hard"
    EXPERT = "Expert"

@dataclass
class DifficultyMetrics:
    """난이도 평가 메트릭"""
    technique_complexity: float  # 기법 복잡도 (0-10)
    tool_requirements: float     # 필요한 도구의 복잡성 (0-10)
    analysis_depth: float        # 분석 깊이 (0-10)
    time_estimation: float       # 예상 소요 시간 (분)
    prerequisite_knowledge: float # 필요한 사전 지식 (0-10)
    total_score: float = 0.0
    
    def __post_init__(self):
        # 가중 평균으로 총점 계산
        weights = [0.25, 0.15, 0.25, 0.20, 0.15]  # 각 메트릭의 가중치
        metrics = [
            self.technique_complexity,
            self.tool_requirements, 
            self.analysis_depth,
            min(self.time_estimation / 60, 10),  # 시간을 10점 척도로 변환
            self.prerequisite_knowledge
        ]
        self.total_score = sum(w * m for w, m in zip(weights, metrics))

class DifficultyClassifier:
    """CTF 문제 난이도 자동 분류기"""
    
    def __init__(self):
        # 기법별 복잡도 점수
        self.technique_complexity = {
            # 기본 기법 (1-3점)
            'metadata': 1.0,
            'strings': 1.5,
            'file_format': 2.0,
            'hex_analysis': 2.5,
            'basic_lsb': 3.0,
            
            # 중급 기법 (3-6점)
            'lsb': 3.5,
            'dct': 4.0,
            'dwt': 4.5,
            'channel_analysis': 4.0,
            'gif_analysis': 4.5,
            'audio_lsb': 5.0,
            'f5': 5.5,
            'pvd': 6.0,
            
            # 고급 기법 (6-8점)
            'edge_adaptive': 6.5,
            'histogram_shifting': 7.0,
            'iwt': 7.5,
            'spread_spectrum': 7.8,
            'qr_reconstruction': 7.5,
            'zip_bomb': 7.0,
            
            # 전문가 기법 (8-10점)
            'network_steganography': 8.5,
            'tcp_steganography': 8.8,
            'dns_tunneling': 9.0,
            'packet_timing': 9.5,
            'http_steganography': 8.5,
            'custom_protocol': 10.0
        }
        
        # 도구별 복잡성
        self.tool_complexity = {
            # 기본 도구 (1-3점)
            'strings': 1.0,
            'file': 1.0,
            'hexdump': 1.5,
            'exiftool': 2.0,
            'binwalk': 2.5,
            'foremost': 2.5,
            'stegsolve': 3.0,
            
            # 중급 도구 (3-6점)  
            'steghide': 3.5,
            'outguess': 4.0,
            'openstego': 4.0,
            'zsteg': 4.5,
            'stegcracker': 5.0,
            'audacity': 5.0,
            'gimp': 5.5,
            
            # 고급 도구 (6-8점)
            'python_scripting': 6.0,
            'custom_tools': 7.0,
            'wireshark': 7.5,
            'volatility': 8.0,
            
            # 전문가 도구 (8-10점)
            'reverse_engineering': 8.5,
            'protocol_analysis': 9.0,
            'custom_algorithms': 9.5,
            'raw_sockets': 10.0
        }
        
        # 키워드별 가중치
        self.description_keywords = {
            # Easy 키워드 (음의 가중치 - 점수 낮춤)
            'easy': -1.0,
            'beginner': -1.0,
            'simple': -0.5,
            'basic': -0.5,
            'straightforward': -0.5,
            
            # Medium 키워드 (중립)
            'medium': 0.0,
            'intermediate': 0.0,
            'moderate': 0.0,
            
            # Hard 키워드 (양의 가중치 - 점수 높춤)
            'hard': 1.0,
            'difficult': 1.0,
            'challenging': 1.5,
            'complex': 1.5,
            'advanced': 2.0,
            
            # Expert 키워드 (높은 가중치)
            'expert': 2.5,
            'insane': 3.0,
            'nightmare': 3.0,
            'impossible': 3.0,
            'reverse': 2.0,
            'custom': 2.0,
            'research': 2.5
        }
        
        # 특별한 패턴들
        self.special_patterns = {
            r'write.*script': 2.0,     # 스크립트 작성 필요
            r'brute.*force': 1.5,      # 브루트포스 필요
            r'network.*traffic': 2.5,  # 네트워크 트래픽 분석
            r'protocol.*analysis': 3.0, # 프로토콜 분석
            r'reverse.*engineer': 3.0,  # 리버스 엔지니어링
            r'custom.*algorithm': 3.5,  # 커스텀 알고리즘
            r'zero.*day': 4.0,         # 제로데이/신기법
            r'machine.*learning': 3.0   # 머신러닝 필요
        }
    
    def classify_difficulty(self, problem) -> Tuple[Difficulty, DifficultyMetrics]:
        """문제의 난이도를 분류합니다."""
        
        # 각 메트릭 계산
        technique_score = self._analyze_technique_complexity(problem.technique)
        tool_score = self._analyze_tool_requirements(problem.description, problem.solution)
        analysis_score = self._analyze_analysis_depth(problem.description, problem.solution)
        time_score = self._estimate_time_requirement(problem)
        knowledge_score = self._analyze_prerequisite_knowledge(problem)
        
        metrics = DifficultyMetrics(
            technique_complexity=technique_score,
            tool_requirements=tool_score,
            analysis_depth=analysis_score,
            time_estimation=time_score,
            prerequisite_knowledge=knowledge_score
        )
        
        # 총점을 기반으로 난이도 결정
        difficulty = self._score_to_difficulty(metrics.total_score)
        
        return difficulty, metrics
    
    def _analyze_technique_complexity(self, technique: str) -> float:
        """기법의 복잡도를 분석합니다."""
        technique_lower = technique.lower()
        
        # 정확한 매치 찾기
        for tech, score in self.technique_complexity.items():
            if tech in technique_lower:
                return score
        
        # 부분 매치 또는 기본값
        if 'lsb' in technique_lower:
            return 3.5
        elif 'dct' in technique_lower or 'dwt' in technique_lower:
            return 4.5
        elif 'network' in technique_lower:
            return 8.0
        else:
            return 5.0  # 기본값
    
    def _analyze_tool_requirements(self, description: str, solution: str) -> float:
        """필요한 도구의 복잡성을 분석합니다."""
        combined_text = f"{description} {solution}".lower()
        max_score = 0.0
        
        # 언급된 도구들의 최대 복잡도 점수 사용
        for tool, score in self.tool_complexity.items():
            if tool.replace('_', ' ') in combined_text or tool in combined_text:
                max_score = max(max_score, score)
        
        # 특별한 패턴 확인
        if 'python' in combined_text or 'script' in combined_text:
            max_score = max(max_score, 6.0)
        if 'custom' in combined_text and 'tool' in combined_text:
            max_score = max(max_score, 8.0)
        
        return max_score if max_score > 0 else 3.0  # 기본값
    
    def _analyze_analysis_depth(self, description: str, solution: str) -> float:
        """분석의 깊이를 평가합니다."""
        combined_text = f"{description} {solution}".lower()
        score = 3.0  # 기본값
        
        # 키워드 기반 점수 조정
        for keyword, weight in self.description_keywords.items():
            if keyword in combined_text:
                score += weight
        
        # 특별한 패턴 확인
        for pattern, weight in self.special_patterns.items():
            if re.search(pattern, combined_text):
                score += weight
        
        # 단계 수 기반 조정
        steps = len(re.findall(r'\d+\.\s|\d+\)\s|step \d+|phase \d+', combined_text))
        if steps > 5:
            score += 2.0
        elif steps > 3:
            score += 1.0
        
        return max(0, min(10, score))  # 0-10 범위로 제한
    
    def _estimate_time_requirement(self, problem) -> float:
        """예상 소요 시간을 추정합니다 (분 단위)."""
        base_time = 30  # 기본 30분
        
        # 점수 기반 시간 조정
        points = getattr(problem, 'points', 100)
        if points <= 50:
            base_time = 15
        elif points <= 150:
            base_time = 30
        elif points <= 300:
            base_time = 60
        elif points <= 500:
            base_time = 120
        else:
            base_time = 240
        
        # 기법별 시간 조정
        technique_multiplier = {
            'metadata': 0.5,
            'strings': 0.5,
            'lsb': 1.0,
            'dct': 1.5,
            'dwt': 1.8,
            'f5': 2.0,
            'network_steganography': 3.0,
            'custom_protocol': 4.0
        }
        
        technique_lower = problem.technique.lower()
        multiplier = 1.0
        for tech, mult in technique_multiplier.items():
            if tech in technique_lower:
                multiplier = mult
                break
        
        return base_time * multiplier
    
    def _analyze_prerequisite_knowledge(self, problem) -> float:
        """필요한 사전 지식 수준을 분석합니다."""
        combined_text = f"{problem.description} {problem.solution}".lower()
        
        knowledge_indicators = {
            # 기초 지식 (1-3점)
            'file format': 2.0,
            'hex editor': 2.5,
            'command line': 2.0,
            
            # 중급 지식 (3-6점)
            'steganography': 4.0,
            'cryptography': 5.0,
            'image processing': 4.5,
            'audio analysis': 5.0,
            
            # 고급 지식 (6-8점)
            'signal processing': 7.0,
            'frequency analysis': 7.5,
            'protocol': 7.0,
            'reverse engineering': 8.0,
            
            # 전문가 지식 (8-10점)
            'network protocol': 8.5,
            'algorithm design': 9.0,
            'security research': 9.5,
            'exploit development': 10.0
        }
        
        max_score = 0.0
        for indicator, score in knowledge_indicators.items():
            if indicator in combined_text:
                max_score = max(max_score, score)
        
        return max_score if max_score > 0 else 4.0  # 기본값
    
    def _score_to_difficulty(self, score: float) -> Difficulty:
        """총점을 난이도로 변환합니다."""
        if score <= 3.0:
            return Difficulty.EASY
        elif score <= 6.0:
            return Difficulty.MEDIUM
        elif score <= 8.0:
            return Difficulty.HARD
        else:
            return Difficulty.EXPERT
    
    def get_difficulty_distribution(self, problems: List) -> Dict[str, int]:
        """문제들의 난이도 분포를 계산합니다."""
        distribution = {
            'Easy': 0,
            'Medium': 0,
            'Hard': 0,
            'Expert': 0
        }
        
        for problem in problems:
            difficulty, _ = self.classify_difficulty(problem)
            distribution[difficulty.value] += 1
        
        return distribution
    
    def recommend_difficulty_adjustment(self, problem) -> Dict[str, str]:
        """난이도 조정 제안을 생성합니다."""
        difficulty, metrics = self.classify_difficulty(problem)
        recommendations = {}
        
        current_difficulty = getattr(problem, 'difficulty', 'Unknown')
        if current_difficulty != difficulty.value:
            recommendations['difficulty_mismatch'] = (
                f"현재 난이도 '{current_difficulty}'를 '{difficulty.value}'로 "
                f"조정하는 것을 권장합니다. (점수: {metrics.total_score:.1f})"
            )
        
        # 개별 메트릭 기반 제안
        if metrics.technique_complexity > 8.0:
            recommendations['high_technique'] = (
                "기법 복잡도가 매우 높습니다. 초보자를 위한 힌트 추가를 고려하세요."
            )
        
        if metrics.time_estimation > 180:  # 3시간 이상
            recommendations['long_time'] = (
                "예상 소요 시간이 3시간을 초과합니다. 중간 체크포인트를 추가하세요."
            )
        
        if metrics.tool_requirements > 8.0:
            recommendations['complex_tools'] = (
                "필요한 도구가 매우 복잡합니다. 도구 사용법 가이드를 제공하세요."
            )
        
        return recommendations
    
    def batch_classify(self, problems: List) -> Dict:
        """다수의 문제를 일괄 분류합니다."""
        results = {
            'classifications': [],
            'distribution': {},
            'recommendations': [],
            'statistics': {}
        }
        
        total_problems = len(problems)
        difficulty_counts = {'Easy': 0, 'Medium': 0, 'Hard': 0, 'Expert': 0}
        total_score = 0.0
        
        for problem in problems:
            difficulty, metrics = self.classify_difficulty(problem)
            
            results['classifications'].append({
                'problem_id': problem.id,
                'title': problem.title,
                'classified_difficulty': difficulty.value,
                'current_difficulty': getattr(problem, 'difficulty', 'Unknown'),
                'score': metrics.total_score,
                'metrics': metrics
            })
            
            difficulty_counts[difficulty.value] += 1
            total_score += metrics.total_score
            
            # 조정 제안 수집
            recommendations = self.recommend_difficulty_adjustment(problem)
            if recommendations:
                results['recommendations'].append({
                    'problem_id': problem.id,
                    'recommendations': recommendations
                })
        
        # 분포 계산
        results['distribution'] = {
            diff: {'count': count, 'percentage': round(count/total_problems*100, 1)}
            for diff, count in difficulty_counts.items()
        }
        
        # 통계 계산
        results['statistics'] = {
            'total_problems': total_problems,
            'average_score': round(total_score / total_problems, 2),
            'recommendations_count': len(results['recommendations']),
            'difficulty_balance': self._analyze_difficulty_balance(difficulty_counts)
        }
        
        return results
    
    def _analyze_difficulty_balance(self, counts: Dict[str, int]) -> Dict[str, str]:
        """난이도 분포의 균형을 분석합니다."""
        total = sum(counts.values())
        percentages = {diff: count/total*100 for diff, count in counts.items()}
        
        analysis = {}
        
        # 이상적인 분포: Easy 30%, Medium 35%, Hard 25%, Expert 10%
        ideal = {'Easy': 30, 'Medium': 35, 'Hard': 25, 'Expert': 10}
        
        for difficulty, ideal_pct in ideal.items():
            actual_pct = percentages[difficulty]
            diff = actual_pct - ideal_pct
            
            if abs(diff) > 10:
                if diff > 0:
                    analysis[f'{difficulty}_excess'] = (
                        f"{difficulty} 난이도가 {diff:.1f}% 과도합니다. "
                        f"일부 문제의 난이도 조정을 고려하세요."
                    )
                else:
                    analysis[f'{difficulty}_deficit'] = (
                        f"{difficulty} 난이도가 {-diff:.1f}% 부족합니다. "
                        f"해당 난이도의 문제를 더 추가하세요."
                    )
        
        return analysis

if __name__ == "__main__":
    # 테스트 및 시연
    from problem_manager import CTFProblem
    
    print("🎯 난이도 분류기 v3.0 시연")
    print("=" * 50)
    
    classifier = DifficultyClassifier()
    
    # 테스트 문제들
    test_problems = [
        CTFProblem(
            id="test1",
            title="Find the Flag",
            description="이미지 파일에서 숨겨진 플래그를 찾으세요.",
            category="steganography",
            technique="metadata",
            difficulty="Easy",
            source="test",
            year=2024,
            points=10,
            files=[],
            flag="flag{test}",
            solution="exiftool로 메타데이터 확인"
        ),
        CTFProblem(
            id="test2", 
            title="Hidden Message",
            description="복잡한 LSB 스테가노그래피가 적용된 이미지를 분석하세요.",
            category="steganography",
            technique="lsb",
            difficulty="Medium",
            source="test",
            year=2024,
            points=200,
            files=[],
            flag="flag{lsb_hidden}",
            solution="Python 스크립트로 LSB 분석 및 추출"
        ),
        CTFProblem(
            id="test3",
            title="Network Covert Channel",
            description="네트워크 패킷의 타이밍을 이용한 고급 스테가노그래피를 분석하세요.",
            category="steganography", 
            technique="packet_timing",
            difficulty="Expert",
            source="test",
            year=2024,
            points=600,
            files=[],
            flag="flag{timing_steganography}",
            solution="패킷 캡처 분석 및 커스텀 알고리즘 개발 필요"
        )
    ]
    
    # 개별 문제 분류
    print("📊 개별 문제 분류 결과:")
    for problem in test_problems:
        difficulty, metrics = classifier.classify_difficulty(problem)
        print(f"\n🎯 {problem.title}")
        print(f"   현재 난이도: {problem.difficulty}")
        print(f"   분류된 난이도: {difficulty.value}")
        print(f"   총점: {metrics.total_score:.1f}/10")
        print(f"   - 기법 복잡도: {metrics.technique_complexity:.1f}")
        print(f"   - 도구 요구사항: {metrics.tool_requirements:.1f}")
        print(f"   - 분석 깊이: {metrics.analysis_depth:.1f}")
        print(f"   - 예상 시간: {metrics.time_estimation:.0f}분")
        print(f"   - 사전 지식: {metrics.prerequisite_knowledge:.1f}")
        
        # 조정 제안
        recommendations = classifier.recommend_difficulty_adjustment(problem)
        if recommendations:
            print(f"   💡 제안사항:")
            for key, suggestion in recommendations.items():
                print(f"      - {suggestion}")
    
    # 일괄 분류
    print(f"\n📈 일괄 분류 결과:")
    batch_results = classifier.batch_classify(test_problems)
    
    print(f"전체 문제 수: {batch_results['statistics']['total_problems']}개")
    print(f"평균 점수: {batch_results['statistics']['average_score']}/10")
    print(f"조정 제안: {batch_results['statistics']['recommendations_count']}개")
    
    print(f"\n난이도 분포:")
    for difficulty, data in batch_results['distribution'].items():
        print(f"  - {difficulty}: {data['count']}개 ({data['percentage']}%)")
    
    # 분포 분석
    balance_analysis = batch_results['statistics']['difficulty_balance']
    if balance_analysis:
        print(f"\n⚖️ 분포 분석:")
        for analysis_key, analysis_text in balance_analysis.items():
            print(f"  - {analysis_text}")
    else:
        print(f"\n✅ 난이도 분포가 적절합니다.")