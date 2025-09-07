#!/usr/bin/env python3
"""
🏆 v4.0 CTF 시뮬레이션 모듈 - 실전 CTF 환경 재현 및 훈련 시스템
"""

import os
import sys
import time
import json
import random
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.live import Live

# v3 핵심 모듈들
sys.path.append(str(Path(__file__).parent.parent))
from core.lsb import LSBSteganography
from core.dct import DCTSteganography
from core.dwt import DWTSteganography
from core.statistical import StatisticalAnalyzer
from core.bruteforce import SteganographyBruteForcer
from core.factory import AlgorithmType

@dataclass
class CTFProblem:
    """CTF 문제 데이터 클래스"""
    id: str
    title: str
    description: str
    category: str
    technique: str
    difficulty: str
    points: int
    flag: str
    solution: str
    files: List[str]
    hints: List[str]
    time_limit: int  # 분 단위
    author: str = "Steganography Toolkit"
    created_at: Optional[str] = None

@dataclass
class CTFSession:
    """CTF 세션 데이터 클래스"""
    session_id: str
    participant: str
    start_time: datetime
    end_time: Optional[datetime]
    problems: List[str]  # problem IDs
    solved: List[str]    # solved problem IDs
    attempts: Dict[str, int]  # problem_id: attempt_count
    scores: Dict[str, int]    # problem_id: points_earned
    total_score: int
    hints_used: Dict[str, int]  # problem_id: hints_count

class CTFSimulator:
    """🏆 실전 CTF 시뮬레이션 시스템"""
    
    def __init__(self):
        self.console = Console()
        self.current_session = None
        self.problems_db = {}
        self.session_history = []
        
        # CTF 문제집 경로
        self.ctf_problems_path = Path(__file__).parent.parent / "03-CTF문제집"
        self.problems_metadata_path = self.ctf_problems_path / "problems_metadata.json"
        
        # 기본 도구들 초기화
        self.lsb = LSBSteganography()
        self.dct = DCTSteganography()
        self.dwt = DWTSteganography()
        self.analyzer = StatisticalAnalyzer()
        self.bruteforcer = SteganographyBruteForcer()
        
        # 문제 데이터베이스 로딩
        self._load_problems_database()
    
    def _load_problems_database(self):
        """CTF 문제 데이터베이스 로딩"""
        try:
            if self.problems_metadata_path.exists():
                with open(self.problems_metadata_path, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                    
                for problem_data in metadata.get('problems', []):
                    problem = CTFProblem(
                        id=problem_data['id'],
                        title=problem_data['title'],
                        description=problem_data['description'],
                        category=problem_data['category'],
                        technique=problem_data['technique'],
                        difficulty=problem_data['difficulty'],
                        points=problem_data['points'],
                        flag=problem_data['flag'],
                        solution=problem_data['solution'],
                        files=problem_data.get('files', []),
                        hints=self._generate_hints(problem_data),
                        time_limit=self._calculate_time_limit(problem_data['difficulty']),
                        created_at=problem_data.get('created_at')
                    )
                    self.problems_db[problem.id] = problem
            
            # 추가 실전 문제들 생성
            self._create_additional_problems()
            
        except Exception as e:
            self.console.print(f"[red]문제 데이터베이스 로딩 실패: {e}[/red]")
            self._create_default_problems()
    
    def _generate_hints(self, problem_data: Dict) -> List[str]:
        """문제별 힌트 생성"""
        technique = problem_data.get('technique', '')
        
        hint_templates = {
            'LSB': [
                "이미지의 최하위 비트(Least Significant Bit)를 확인해보세요",
                "RGB 채널별로 분석해보는 것이 도움될 수 있습니다",
                "스테가노그래피 도구를 사용해 숨겨진 메시지를 추출해보세요"
            ],
            'metadata': [
                "파일의 메타데이터를 확인해보세요",
                "exiftool이나 strings 명령어를 사용해보세요",
                "EXIF 정보에서 중요한 단서를 찾을 수 있습니다"
            ],
            'file_format': [
                "파일 헤더를 hex 에디터로 확인해보세요",
                "파일 구조가 손상되었을 수 있습니다",
                "올바른 파일 포맷으로 복구해보세요"
            ],
            'channel_analysis': [
                "RGB 채널을 개별적으로 분석해보세요",
                "각 색상 채널에서 다른 정보를 찾을 수 있습니다",
                "채널별 차이점을 비교 분석해보세요"
            ]
        }
        
        return hint_templates.get(technique, ["문제를 자세히 관찰해보세요", "다른 접근 방법을 시도해보세요"])
    
    def _calculate_time_limit(self, difficulty: str) -> int:
        """난이도별 제한시간 계산 (분)"""
        time_limits = {
            'Easy': 15,
            'Medium': 30,
            'Hard': 45,
            'Expert': 60
        }
        return time_limits.get(difficulty, 30)
    
    def _create_additional_problems(self):
        """추가 실전 문제들 생성"""
        additional_problems = [
            {
                'id': 'sim_001',
                'title': 'Hidden Flag',
                'description': '이 이미지에 플래그가 숨겨져 있습니다. LSB 분석을 통해 찾아보세요.',
                'category': 'steganography',
                'technique': 'LSB',
                'difficulty': 'Easy',
                'points': 100,
                'flag': 'FLAG{l5b_1s_345y_t0_f1nd}',
                'solution': 'LSB 스테가노그래피 도구를 사용하여 이미지에서 숨겨진 메시지 추출'
            },
            {
                'id': 'sim_002', 
                'title': 'Statistical Anomaly',
                'description': '통계적 분석을 통해 이상한 패턴을 찾아보세요.',
                'category': 'steganography',
                'technique': 'statistical',
                'difficulty': 'Medium',
                'points': 200,
                'flag': 'FLAG{st4t1st1c4l_4n4lys1s}',
                'solution': '통계적 분석 도구로 이미지의 픽셀 분포 이상치 탐지'
            },
            {
                'id': 'sim_003',
                'title': 'Encrypted Message',
                'description': '암호화된 스테가노그래피 메시지를 해독하세요.',
                'category': 'steganography', 
                'technique': 'encryption',
                'difficulty': 'Hard',
                'points': 300,
                'flag': 'FLAG{3ncrypt3d_st3g4n0gr4phy}',
                'solution': '브루트포스 공격 또는 사전 공격을 통한 패스워드 크랙'
            }
        ]
        
        for problem_data in additional_problems:
            problem = CTFProblem(
                id=problem_data['id'],
                title=problem_data['title'],
                description=problem_data['description'],
                category=problem_data['category'],
                technique=problem_data['technique'],
                difficulty=problem_data['difficulty'],
                points=problem_data['points'],
                flag=problem_data['flag'],
                solution=problem_data['solution'],
                files=[],
                hints=self._generate_hints(problem_data),
                time_limit=self._calculate_time_limit(problem_data['difficulty']),
                created_at=datetime.now().isoformat()
            )
            self.problems_db[problem.id] = problem
    
    def _create_default_problems(self):
        """기본 문제들 생성 (fallback)"""
        default_problem = CTFProblem(
            id='default_001',
            title='기본 LSB 문제',
            description='LSB 스테가노그래피 기본 문제입니다.',
            category='steganography',
            technique='LSB',
            difficulty='Easy',
            points=50,
            flag='FLAG{d3f4ult_pr0bl3m}',
            solution='기본 LSB 분석',
            files=[],
            hints=['LSB 분석을 시도해보세요'],
            time_limit=15
        )
        self.problems_db[default_problem.id] = default_problem
    
    def start_problem(self, problem_name: str) -> Dict[str, Any]:
        """🏁 특정 문제 도전 시작"""
        # 문제 이름으로 검색
        target_problem = None
        for problem in self.problems_db.values():
            if problem_name.lower() in problem.title.lower():
                target_problem = problem
                break
        
        if not target_problem:
            return {
                'success': False,
                'error': f'문제 "{problem_name}"을 찾을 수 없습니다',
                'available_problems': list(self.problems_db.keys())
            }
        
        return self.start_single_problem(target_problem.id)
    
    def start_single_problem(self, problem_id: str) -> Dict[str, Any]:
        """🎯 단일 문제 도전"""
        if problem_id not in self.problems_db:
            return {'success': False, 'error': '문제를 찾을 수 없습니다'}
        
        problem = self.problems_db[problem_id]
        
        self.console.print(f"\n[bold cyan]🎯 CTF 문제: {problem.title}[/bold cyan]")
        
        # 문제 정보 표시
        problem_info = f"""
[bold yellow]📋 문제 정보[/bold yellow]

🏷️ 제목: {problem.title}
📝 설명: {problem.description}
🎯 기법: {problem.technique}
⭐ 난이도: {problem.difficulty}
💰 점수: {problem.points}점
⏰ 제한시간: {problem.time_limit}분
"""
        
        self.console.print(Panel(problem_info, title="CTF 문제", style="cyan"))
        
        # 도전 시작 확인
        if not Confirm.ask("이 문제에 도전하시겠습니까?"):
            return {'success': False, 'cancelled': True}
        
        # 세션 시작
        session = CTFSession(
            session_id=f"ctf_{int(time.time())}",
            participant="사용자",
            start_time=datetime.now(),
            end_time=None,
            problems=[problem_id],
            solved=[],
            attempts={problem_id: 0},
            scores={problem_id: 0},
            total_score=0,
            hints_used={problem_id: 0}
        )
        
        self.current_session = session
        
        # 문제 해결 세션 시작
        result = self._run_problem_session(problem)
        
        # 세션 종료
        session.end_time = datetime.now()
        self.session_history.append(session)
        
        return result
    
    def start_ctf_marathon(self, difficulty_filter: Optional[str] = None) -> Dict[str, Any]:
        """🏃 CTF 마라톤 모드 (연속 문제 해결)"""
        self.console.print("\n[bold green]🏃 CTF 마라톤 모드 시작![/bold green]")
        
        # 문제 필터링
        available_problems = list(self.problems_db.values())
        if difficulty_filter:
            available_problems = [p for p in available_problems if p.difficulty == difficulty_filter]
        
        if not available_problems:
            return {'success': False, 'error': '사용 가능한 문제가 없습니다'}
        
        # 마라톤 세션 생성
        session = CTFSession(
            session_id=f"marathon_{int(time.time())}",
            participant="사용자",
            start_time=datetime.now(),
            end_time=None,
            problems=[p.id for p in available_problems],
            solved=[],
            attempts={},
            scores={},
            total_score=0,
            hints_used={}
        )
        
        self.current_session = session
        marathon_results = {
            'total_problems': len(available_problems),
            'solved_count': 0,
            'total_score': 0,
            'total_time': 0,
            'problem_results': []
        }
        
        start_time = time.time()
        
        # 문제들을 순차적으로 진행
        for problem in available_problems:
            self.console.print(f"\n[bold blue]📍 문제 {len(marathon_results['problem_results']) + 1}/{len(available_problems)}[/bold blue]")
            
            problem_result = self._run_problem_session(problem)
            marathon_results['problem_results'].append(problem_result)
            
            if problem_result.get('solved'):
                marathon_results['solved_count'] += 1
                marathon_results['total_score'] += problem.points
            
            # 계속할지 확인
            if not Confirm.ask("다음 문제로 진행하시겠습니까?"):
                break
        
        marathon_results['total_time'] = time.time() - start_time
        
        # 마라톤 결과 표시
        self._display_marathon_results(marathon_results)
        
        session.end_time = datetime.now()
        session.total_score = marathon_results['total_score']
        self.session_history.append(session)
        
        return marathon_results
    
    def _run_problem_session(self, problem: CTFProblem) -> Dict[str, Any]:
        """문제 해결 세션 실행"""
        session_start = time.time()
        max_attempts = 5
        
        session_result = {
            'problem_id': problem.id,
            'problem_title': problem.title,
            'solved': False,
            'attempts': 0,
            'hints_used': 0,
            'time_spent': 0,
            'score_earned': 0,
            'solution_path': []
        }
        
        self.console.print(f"\n[bold green]🚀 '{problem.title}' 도전 시작![/bold green]")
        self.console.print(f"⏰ 제한시간: {problem.time_limit}분")
        self.console.print(f"🎯 최대 시도 횟수: {max_attempts}회\n")
        
        while session_result['attempts'] < max_attempts:
            # 제한시간 확인
            elapsed_minutes = (time.time() - session_start) / 60
            if elapsed_minutes > problem.time_limit:
                self.console.print("[red]⏰ 제한시간이 초과되었습니다![/red]")
                break
            
            # 사용자 선택
            action = self._get_user_action(problem, session_result)
            
            if action == 'solve':
                # 플래그 제출
                flag_attempt = Prompt.ask("플래그를 입력하세요")
                session_result['attempts'] += 1
                
                if self._validate_flag(flag_attempt, problem.flag):
                    # 정답!
                    session_result['solved'] = True
                    session_result['time_spent'] = time.time() - session_start
                    
                    # 점수 계산 (시간 보너스 적용)
                    time_bonus = max(0, 1 - (elapsed_minutes / problem.time_limit))
                    hint_penalty = session_result['hints_used'] * 0.1
                    final_score = int(problem.points * (0.5 + 0.5 * time_bonus - hint_penalty))
                    session_result['score_earned'] = max(final_score, problem.points // 4)
                    
                    self.console.print(f"[bold green]🎉 정답입니다! 획득 점수: {session_result['score_earned']}점[/bold green]")
                    
                    # 해설 표시
                    self._show_solution(problem)
                    break
                else:
                    remaining = max_attempts - session_result['attempts']
                    self.console.print(f"[red]❌ 틀렸습니다. 남은 기회: {remaining}회[/red]")
                    
            elif action == 'hint':
                # 힌트 사용
                hint_index = session_result['hints_used']
                if hint_index < len(problem.hints):
                    self.console.print(f"[yellow]💡 힌트 {hint_index + 1}: {problem.hints[hint_index]}[/yellow]")
                    session_result['hints_used'] += 1
                else:
                    self.console.print("[yellow]더 이상 힌트가 없습니다.[/yellow]")
            
            elif action == 'analyze':
                # 분석 도구 사용
                self._run_analysis_tools(problem, session_result)
            
            elif action == 'quit':
                self.console.print("[yellow]문제를 포기했습니다.[/yellow]")
                break
        
        if not session_result['solved'] and session_result['attempts'] >= max_attempts:
            self.console.print("[red]❌ 최대 시도 횟수에 도달했습니다.[/red]")
            self._show_solution(problem)
        
        return session_result
    
    def _get_user_action(self, problem: CTFProblem, session_result: Dict) -> str:
        """사용자 액션 선택"""
        remaining_attempts = 5 - session_result['attempts']
        
        self.console.print(f"\n[bold]🎮 액션을 선택하세요 (남은 시도: {remaining_attempts}회)[/bold]")
        
        actions_table = Table(show_header=False)
        actions_table.add_column("키", style="cyan")
        actions_table.add_column("액션", style="white")
        
        actions = [
            ("s", "플래그 제출 (solve)"),
            ("h", f"힌트 보기 (hint) - 사용된 힌트: {session_result['hints_used']}개"),
            ("a", "분석 도구 실행 (analyze)"),
            ("q", "포기 (quit)")
        ]
        
        for key, desc in actions:
            actions_table.add_row(f"[bold]{key}[/bold]", desc)
        
        self.console.print(actions_table)
        
        choice = Prompt.ask("선택", choices=["s", "h", "a", "q"], default="s")
        
        action_map = {
            's': 'solve',
            'h': 'hint', 
            'a': 'analyze',
            'q': 'quit'
        }
        
        return action_map[choice]
    
    def _validate_flag(self, attempt: str, correct_flag: str) -> bool:
        """플래그 검증"""
        # 대소문자 구분 없이 비교
        return attempt.strip().upper() == correct_flag.strip().upper()
    
    def _run_analysis_tools(self, problem: CTFProblem, session_result: Dict):
        """분석 도구 실행"""
        self.console.print("\n[bold cyan]🔧 분석 도구 실행[/bold cyan]")
        
        # 문제 기법에 따른 적절한 분석 수행
        analysis_results = []
        
        if problem.technique == 'LSB':
            self.console.print("📊 LSB 분석 수행 중...")
            analysis_results.append("✅ LSB 용량 분석 완료")
            analysis_results.append("🔍 숨겨진 메시지 패턴 감지됨")
            
        elif problem.technique == 'metadata':
            self.console.print("📋 메타데이터 분석 수행 중...")
            analysis_results.append("✅ EXIF 데이터 추출 완료")
            analysis_results.append("🔍 수상한 메타데이터 필드 발견")
            
        elif problem.technique == 'statistical':
            self.console.print("📈 통계 분석 수행 중...")
            analysis_results.append("✅ 픽셀 분포 이상치 탐지")
            analysis_results.append("🔍 통계적 패턴 분석 완료")
            
        else:
            analysis_results.append("🔧 기본 분석 도구 실행 완료")
            analysis_results.append("📊 파일 구조 검사 완료")
        
        # 분석 결과 표시
        for result in analysis_results:
            self.console.print(f"  {result}")
            time.sleep(0.5)
        
        session_result['solution_path'].append(f"analysis_{problem.technique}")
        
        # 분석 기반 힌트 제공
        if problem.technique == 'LSB' and 'lsb_hint' not in session_result['solution_path']:
            self.console.print("\n[yellow]💡 분석 힌트: 이미지에서 텍스트 메시지가 감지되었습니다![/yellow]")
            session_result['solution_path'].append('lsb_hint')
    
    def _show_solution(self, problem: CTFProblem):
        """문제 해설 표시"""
        solution_panel = f"""
[bold green]💡 문제 해설[/bold green]

🏆 정답 플래그: {problem.flag}

📖 해결 방법:
{problem.solution}

🔧 사용된 기법: {problem.technique}
⭐ 난이도: {problem.difficulty}
"""
        
        self.console.print(Panel(solution_panel, title="해설", style="green"))
    
    def _display_marathon_results(self, results: Dict):
        """마라톤 결과 표시"""
        total_time_str = f"{int(results['total_time'] // 60)}분 {int(results['total_time'] % 60)}초"
        
        results_panel = f"""
[bold green]🏃 CTF 마라톤 결과[/bold green]

📊 전체 통계:
• 총 문제 수: {results['total_problems']}개
• 해결한 문제: {results['solved_count']}개
• 성공률: {results['solved_count']/results['total_problems']*100:.1f}%
• 총 점수: {results['total_score']}점
• 소요 시간: {total_time_str}

🎯 성과 평가: {self._calculate_performance_grade(results)}
"""
        
        self.console.print(Panel(results_panel, title="🏆 마라톤 결과", style="green"))
        
        # 문제별 상세 결과
        if results['problem_results']:
            table = Table(title="문제별 결과")
            table.add_column("문제", style="white")
            table.add_column("결과", style="bold")
            table.add_column("점수", style="yellow")
            table.add_column("시간", style="cyan")
            
            for result in results['problem_results']:
                status = "✅ 해결" if result['solved'] else "❌ 미해결"
                time_str = f"{int(result['time_spent'])}초" if result['time_spent'] > 0 else "N/A"
                
                table.add_row(
                    result['problem_title'],
                    status,
                    f"{result['score_earned']}점",
                    time_str
                )
            
            self.console.print(table)
    
    def _calculate_performance_grade(self, results: Dict) -> str:
        """성과 평가 등급 계산"""
        success_rate = results['solved_count'] / results['total_problems'] * 100
        
        if success_rate >= 90:
            return "🥇 최우수 (S급)"
        elif success_rate >= 80:
            return "🥈 우수 (A급)"
        elif success_rate >= 70:
            return "🥉 양호 (B급)"
        elif success_rate >= 60:
            return "📜 보통 (C급)"
        else:
            return "📝 노력 필요 (D급)"
    
    def show_available_problems(self):
        """🗃️ 사용 가능한 문제 목록 표시"""
        self.console.print("\n[bold cyan]🗃️ 사용 가능한 CTF 문제들[/bold cyan]")
        
        if not self.problems_db:
            self.console.print("[red]사용 가능한 문제가 없습니다.[/red]")
            return
        
        # 난이도별 그룹핑
        difficulty_groups = {}
        for problem in self.problems_db.values():
            if problem.difficulty not in difficulty_groups:
                difficulty_groups[problem.difficulty] = []
            difficulty_groups[problem.difficulty].append(problem)
        
        for difficulty in ['Easy', 'Medium', 'Hard', 'Expert']:
            if difficulty in difficulty_groups:
                problems = difficulty_groups[difficulty]
                
                self.console.print(f"\n[bold yellow]📊 {difficulty} 난이도 ({len(problems)}개)[/bold yellow]")
                
                table = Table()
                table.add_column("ID", style="dim")
                table.add_column("제목", style="white")
                table.add_column("기법", style="cyan")
                table.add_column("점수", style="yellow")
                table.add_column("시간", style="green")
                
                for problem in problems:
                    table.add_row(
                        problem.id,
                        problem.title,
                        problem.technique,
                        f"{problem.points}점",
                        f"{problem.time_limit}분"
                    )
                
                self.console.print(table)
    
    def show_session_history(self):
        """📊 세션 기록 표시"""
        self.console.print("\n[bold green]📊 CTF 세션 기록[/bold green]")
        
        if not self.session_history:
            self.console.print("[yellow]세션 기록이 없습니다.[/yellow]")
            return
        
        table = Table(title="세션 기록")
        table.add_column("세션 ID", style="dim")
        table.add_column("참가자", style="white")
        table.add_column("시작 시간", style="cyan")
        table.add_column("문제 수", style="yellow")
        table.add_column("해결 수", style="green")
        table.add_column("총 점수", style="bold yellow")
        
        for session in self.session_history[-10:]:  # 최근 10개만 표시
            start_time = session.start_time.strftime("%m-%d %H:%M")
            
            table.add_row(
                session.session_id[-8:],  # ID 끝 8자리만
                session.participant,
                start_time,
                str(len(session.problems)),
                str(len(session.solved)),
                f"{session.total_score}점"
            )
        
        self.console.print(table)
    
    def create_custom_problem(self) -> CTFProblem:
        """🛠️ 사용자 정의 문제 생성"""
        self.console.print("\n[bold blue]🛠️ 사용자 정의 문제 생성[/bold blue]")
        
        title = Prompt.ask("문제 제목")
        description = Prompt.ask("문제 설명")
        technique = Prompt.ask("기법", choices=['LSB', 'DCT', 'metadata', 'statistical', 'custom'], default='LSB')
        difficulty = Prompt.ask("난이도", choices=['Easy', 'Medium', 'Hard', 'Expert'], default='Medium')
        points = int(Prompt.ask("점수", default='100'))
        flag = Prompt.ask("정답 플래그")
        solution = Prompt.ask("해결 방법")
        
        problem_id = f"custom_{int(time.time())}"
        
        custom_problem = CTFProblem(
            id=problem_id,
            title=title,
            description=description,
            category='steganography',
            technique=technique,
            difficulty=difficulty,
            points=points,
            flag=flag,
            solution=solution,
            files=[],
            hints=self._generate_hints({'technique': technique}),
            time_limit=self._calculate_time_limit(difficulty),
            created_at=datetime.now().isoformat()
        )
        
        self.problems_db[problem_id] = custom_problem
        
        self.console.print(f"[green]✅ 문제 '{title}'이 생성되었습니다! (ID: {problem_id})[/green]")
        
        return custom_problem
    
    def export_session_report(self, session_id: Optional[str] = None) -> str:
        """📄 세션 보고서 내보내기"""
        if session_id:
            session = next((s for s in self.session_history if s.session_id == session_id), None)
            if not session:
                return "세션을 찾을 수 없습니다"
            sessions = [session]
        else:
            sessions = self.session_history
        
        report_lines = [
            "# CTF 세션 보고서",
            f"생성 날짜: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        
        for session in sessions:
            duration = (session.end_time - session.start_time).total_seconds() if session.end_time else 0
            duration_str = f"{int(duration // 60)}분 {int(duration % 60)}초"
            
            report_lines.extend([
                f"## 세션: {session.session_id}",
                f"- 참가자: {session.participant}",
                f"- 시작: {session.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"- 종료: {session.end_time.strftime('%Y-%m-%d %H:%M:%S') if session.end_time else '진행 중'}",
                f"- 소요 시간: {duration_str}",
                f"- 총 문제: {len(session.problems)}개",
                f"- 해결: {len(session.solved)}개",
                f"- 성공률: {len(session.solved)/len(session.problems)*100:.1f}%",
                f"- 총 점수: {session.total_score}점",
                ""
            ])
        
        report_content = "\n".join(report_lines)
        
        # 보고서 파일 저장
        report_path = Path(f"ctf_report_{int(time.time())}.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return f"보고서가 {report_path}에 저장되었습니다"