#!/usr/bin/env python3
"""
🚀 v4.0 스테가노그래피 툴킷 - 실전 테스트 메인 인터페이스

실제 CTF 환경에서 사용할 수 있는 통합 CLI 도구
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Dict, Any
import json

# v3 코어 모듈 임포트
sys.path.append(str(Path(__file__).parent))
from core.lsb import LSBSteganography
from core.dct import DCTSteganography  
from core.dwt import DWTSteganography
from core.statistical import StatisticalAnalyzer
from core.bruteforce import SteganographyBruteForcer
from core.factory import SteganographyFactory, AlgorithmType

# v4 새로운 모듈들
from v4_modules.cli_interface import CLIInterface
from v4_modules.test_automation import TestAutomation
from v4_modules.performance_monitor import PerformanceMonitor
from v4_modules.ctf_simulator import CTFSimulator

class SteganographyToolkitV4:
    """v4.0 메인 툴킷 클래스"""
    
    def __init__(self):
        self.cli = CLIInterface()
        self.test_automation = TestAutomation()
        self.performance_monitor = PerformanceMonitor()
        self.ctf_simulator = CTFSimulator()
        
        # v3 기존 도구들
        self.lsb = LSBSteganography()
        self.analyzer = StatisticalAnalyzer()
        self.bruteforcer = SteganographyBruteForcer()
    
    def run_quick_test(self):
        """⚡ 빠른 기능 검증 테스트"""
        return self.test_automation.run_quick_validation()
    
    def run_full_test(self):
        """🔍 전체 기능 테스트 스위트"""
        return self.test_automation.run_comprehensive_test()
    
    def simulate_ctf(self, problem_name: str):
        """🏆 CTF 문제 시뮬레이션 모드"""
        return self.ctf_simulator.start_problem(problem_name)
    
    def analyze_image(self, image_path: str):
        """🔬 이미지 종합 분석"""
        return self.test_automation.analyze_image_comprehensive(image_path)
    
    def benchmark_performance(self):
        """📊 성능 벤치마크"""
        return self.performance_monitor.run_full_benchmark()

def main():
    """메인 엔트리 포인트"""
    parser = argparse.ArgumentParser(
        description='🚀 v4.0 스테가노그래피 툴킷 - 실전 테스트 도구',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python v4_main.py --quick-test                    # 빠른 기능 검증
  python v4_main.py --full-test                     # 전체 테스트 스위트  
  python v4_main.py --ctf "hit_a_brick_wall"        # CTF 문제 시뮬레이션
  python v4_main.py --analyze image.png             # 이미지 종합 분석
  python v4_main.py --benchmark                     # 성능 벤치마크
  python v4_main.py --interactive                   # 대화형 모드
        """
    )
    
    parser.add_argument('--quick-test', action='store_true', help='빠른 기능 검증 테스트')
    parser.add_argument('--full-test', action='store_true', help='전체 기능 테스트 스위트')
    parser.add_argument('--ctf', metavar='PROBLEM', help='CTF 문제 시뮬레이션')
    parser.add_argument('--analyze', metavar='IMAGE', help='이미지 종합 분석')
    parser.add_argument('--benchmark', action='store_true', help='성능 벤치마크')
    parser.add_argument('--interactive', action='store_true', help='대화형 모드')
    parser.add_argument('--verbose', '-v', action='store_true', help='상세 출력')
    
    args = parser.parse_args()
    
    # 툴킷 초기화
    toolkit = SteganographyToolkitV4()
    
    # 명령어 처리
    if args.quick_test:
        print("⚡ 빠른 기능 검증 테스트 시작...")
        result = toolkit.run_quick_test()
        print(f"테스트 결과: {'✅ 성공' if result['success'] else '❌ 실패'}")
        
    elif args.full_test:
        print("🔍 전체 기능 테스트 스위트 실행...")
        result = toolkit.run_full_test()
        print(f"전체 테스트 결과: {result['summary']}")
        
    elif args.ctf:
        print(f"🏆 CTF 문제 '{args.ctf}' 시뮬레이션 시작...")
        result = toolkit.simulate_ctf(args.ctf)
        
    elif args.analyze:
        print(f"🔬 이미지 '{args.analyze}' 종합 분석...")
        result = toolkit.analyze_image(args.analyze)
        
    elif args.benchmark:
        print("📊 성능 벤치마크 실행...")
        result = toolkit.benchmark_performance()
        
    elif args.interactive:
        print("🎛️ 대화형 모드 시작...")
        toolkit.cli.start_interactive_mode()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()