"""
통계 분석 모듈 (v2.0 신규)
다중 파일 통계 비교 및 이상치 자동 탐지 도구입니다.

주요 기능:
- HSV/LAB 색공간 분포 분석
- 통계적 이상치 자동 탐지
- RGB-to-ASCII 패턴 인식  
- 엔트로피 기반 분석
- CTF 문제: Turtles All The Way Down 해결
"""

import os
import numpy as np
from PIL import Image
import colorsys
from typing import Dict, List, Optional, Any, Tuple
import statistics
from collections import Counter
import base64
import hashlib
import re

class StatisticalAnalyzer:
    """통계 분석 클래스"""
    
    def __init__(self):
        self.supported_formats = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']
    
    def analyze_multiple_files(self, file_list: List[str]) -> Dict[str, Any]:
        """다중 파일 통계 비교 분석"""
        print(f"🔍 {len(file_list)}개 파일 통계 분석 시작...")
        
        results = {
            'file_count': len(file_list),
            'file_analyses': {},
            'statistical_summary': {},
            'outliers': [],
            'patterns': {},
            'recommendations': []
        }
        
        # 개별 파일 분석
        analyses = {}
        for i, file_path in enumerate(file_list, 1):
            print(f"  📊 {i}/{len(file_list)}: {os.path.basename(file_path)}")
            try:
                analysis = self.analyze_single_file(file_path)
                analyses[file_path] = analysis
            except Exception as e:
                print(f"    ❌ 분석 실패: {e}")
                analyses[file_path] = {'error': str(e)}
        
        results['file_analyses'] = analyses
        
        # 통계적 비교 분석
        print("\n📈 통계적 비교 분석 중...")
        results['statistical_summary'] = self._compare_statistics(analyses)
        
        # 이상치 탐지
        print("🎯 이상치 자동 탐지 중...")
        results['outliers'] = self._detect_outliers(analyses)
        
        # 패턴 인식
        print("🔍 숨겨진 패턴 검색 중...")
        results['patterns'] = self._detect_patterns(analyses)
        
        # 추천 사항
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def analyze_single_file(self, file_path: str) -> Dict[str, Any]:
        """개별 파일 상세 분석"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")
        
        # 이미지 로드
        img = Image.open(file_path)
        img_array = np.array(img)
        
        analysis = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'dimensions': img.size,
            'mode': img.mode,
            'channels': len(img.getbands()),
            'aspect_ratio': img.size[0] / img.size[1] if img.size[1] > 0 else 0,
            'is_square': img.size[0] == img.size[1],
        }
        
        # RGB 분석
        if len(img_array.shape) >= 3:
            analysis.update(self._analyze_rgb_distribution(img_array))
            analysis.update(self._analyze_hsv_distribution(img_array))
            analysis.update(self._calculate_entropy(img_array))
            analysis.update(self._detect_ascii_patterns(img_array))
        
        # 파일 해시
        analysis['file_hash'] = self._calculate_file_hash(file_path)
        
        return analysis
    
    def _analyze_rgb_distribution(self, img_array: np.ndarray) -> Dict[str, Any]:
        """RGB 색상 분포 분석"""
        rgb_stats = {}
        
        for i, channel in enumerate(['red', 'green', 'blue']):
            if i < img_array.shape[2]:
                channel_data = img_array[:, :, i].flatten()
                rgb_stats[f'{channel}_mean'] = float(np.mean(channel_data))
                rgb_stats[f'{channel}_std'] = float(np.std(channel_data))
                rgb_stats[f'{channel}_min'] = int(np.min(channel_data))
                rgb_stats[f'{channel}_max'] = int(np.max(channel_data))
                
                # 히스토그램 분석
                hist, _ = np.histogram(channel_data, bins=256, range=(0, 256))
                rgb_stats[f'{channel}_histogram_peaks'] = len([i for i, v in enumerate(hist) if v > np.mean(hist) * 2])
                rgb_stats[f'{channel}_dominant_values'] = [int(i) for i in np.argsort(hist)[-5:]]
        
        return {'rgb_analysis': rgb_stats}
    
    def _analyze_hsv_distribution(self, img_array: np.ndarray) -> Dict[str, Any]:
        """HSV 색공간 분포 분석 - CTF 핵심!"""
        # RGB → HSV 변환 (4채널 RGBA 처리)
        if len(img_array.shape) >= 3 and img_array.shape[2] == 4:  # RGBA
            rgb_array = img_array[:, :, :3]  # 알파 채널 제거
        elif len(img_array.shape) >= 3:
            rgb_array = img_array
        else:
            return {'hsv_analysis': {'error': 'Invalid image format'}}
            
        hsv_array = np.zeros((rgb_array.shape[0], rgb_array.shape[1], 3), dtype=np.float32)
        
        for i in range(rgb_array.shape[0]):
            for j in range(rgb_array.shape[1]):
                r, g, b = rgb_array[i, j, :3] / 255.0
                h, s, v = colorsys.rgb_to_hsv(r, g, b)
                hsv_array[i, j] = [h * 360, s * 100, v * 100]  # 정규화
        
        hsv_stats = {}
        for i, channel in enumerate(['hue', 'saturation', 'value']):
            channel_data = hsv_array[:, :, i].flatten()
            hsv_stats[f'{channel}_mean'] = float(np.mean(channel_data))
            hsv_stats[f'{channel}_std'] = float(np.std(channel_data))
            hsv_stats[f'{channel}_variance'] = float(np.var(channel_data))
            
            # 분산이 비정상적으로 높거나 낮은 경우 감지
            if channel == 'hue':
                hsv_stats['hue_anomaly'] = hsv_stats['hue_variance'] > 10000 or hsv_stats['hue_variance'] < 100
            elif channel == 'saturation':
                hsv_stats['saturation_anomaly'] = hsv_stats['saturation_variance'] > 1000 or hsv_stats['saturation_variance'] < 10
            elif channel == 'value':
                hsv_stats['value_anomaly'] = hsv_stats['value_variance'] > 1000 or hsv_stats['value_variance'] < 50
        
        return {'hsv_analysis': hsv_stats}
    
    def _calculate_entropy(self, img_array: np.ndarray) -> Dict[str, Any]:
        """엔트로피 기반 무작위성 분석"""
        entropy_stats = {}
        
        # 전체 이미지 엔트로피
        flattened = img_array.flatten()
        hist, _ = np.histogram(flattened, bins=256, range=(0, 256))
        hist = hist / hist.sum()  # 정규화
        entropy = -np.sum(hist * np.log2(hist + 1e-10))  # 엔트로피 계산
        
        entropy_stats['total_entropy'] = float(entropy)
        entropy_stats['entropy_normalized'] = float(entropy / 8.0)  # 8비트 기준 정규화
        
        # 채널별 엔트로피
        if len(img_array.shape) >= 3:
            for i, channel in enumerate(['red', 'green', 'blue']):
                if i < img_array.shape[2]:
                    channel_data = img_array[:, :, i].flatten()
                    hist, _ = np.histogram(channel_data, bins=256, range=(0, 256))
                    hist = hist / hist.sum()
                    channel_entropy = -np.sum(hist * np.log2(hist + 1e-10))
                    entropy_stats[f'{channel}_entropy'] = float(channel_entropy)
        
        return {'entropy_analysis': entropy_stats}
    
    def _detect_ascii_patterns(self, img_array: np.ndarray) -> Dict[str, Any]:
        """RGB-to-ASCII 패턴 자동 감지"""
        patterns = {
            'ascii_candidates': [],
            'text_probability': 0.0,
            'readable_sequences': []
        }
        
        # RGB 값들을 ASCII로 해석 시도
        if len(img_array.shape) >= 3 and img_array.shape[2] >= 3:
            # 이미지를 1차원으로 변환
            rgb_flat = img_array.reshape(-1, img_array.shape[2])
            
            ascii_candidates = []
            for pixel in rgb_flat[:1000]:  # 처음 1000픽셀만 검사 (성능)
                for value in pixel[:3]:  # RGB 채널
                    if 32 <= value <= 126:  # 인쇄 가능한 ASCII 범위
                        ascii_candidates.append(chr(value))
            
            patterns['ascii_candidates'] = ascii_candidates[:100]  # 처음 100개만
            
            # 텍스트 패턴 확률 계산
            printable_ratio = len([c for c in ascii_candidates if c.isprintable()]) / max(len(ascii_candidates), 1)
            patterns['text_probability'] = printable_ratio
            
            # 연속된 읽을 수 있는 문자열 찾기
            ascii_string = ''.join(ascii_candidates)
            readable_sequences = []
            current_seq = ""
            
            for char in ascii_string:
                if char.isalnum() or char in ' .,!?-_':
                    current_seq += char
                else:
                    if len(current_seq) >= 4:  # 4글자 이상의 시퀀스만
                        readable_sequences.append(current_seq.strip())
                    current_seq = ""
            
            # 마지막 시퀀스 처리
            if len(current_seq) >= 4:
                readable_sequences.append(current_seq.strip())
            
            patterns['readable_sequences'] = readable_sequences[:10]  # 상위 10개만
        
        return {'pattern_analysis': patterns}
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """파일 해시 계산"""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _compare_statistics(self, analyses: Dict[str, Dict]) -> Dict[str, Any]:
        """통계적 비교 분석"""
        summary = {
            'dimension_stats': {},
            'color_stats': {},
            'entropy_stats': {},
            'file_size_stats': {}
        }
        
        valid_analyses = {k: v for k, v in analyses.items() if 'error' not in v}
        
        if not valid_analyses:
            return summary
        
        # 크기 통계
        widths = [analysis['dimensions'][0] for analysis in valid_analyses.values()]
        heights = [analysis['dimensions'][1] for analysis in valid_analyses.values()]
        aspect_ratios = [analysis['aspect_ratio'] for analysis in valid_analyses.values()]
        file_sizes = [analysis['file_size'] for analysis in valid_analyses.values()]
        
        summary['dimension_stats'] = {
            'width_mean': statistics.mean(widths),
            'width_std': statistics.stdev(widths) if len(widths) > 1 else 0,
            'height_mean': statistics.mean(heights),
            'height_std': statistics.stdev(heights) if len(heights) > 1 else 0,
            'aspect_ratio_mean': statistics.mean(aspect_ratios),
            'aspect_ratio_std': statistics.stdev(aspect_ratios) if len(aspect_ratios) > 1 else 0,
            'square_count': sum(1 for analysis in valid_analyses.values() if analysis['is_square'])
        }
        
        summary['file_size_stats'] = {
            'size_mean': statistics.mean(file_sizes),
            'size_std': statistics.stdev(file_sizes) if len(file_sizes) > 1 else 0,
            'size_min': min(file_sizes),
            'size_max': max(file_sizes)
        }
        
        # HSV 분산 통계 (핵심!)
        hsv_variances = []
        for analysis in valid_analyses.values():
            if 'hsv_analysis' in analysis:
                hsv_var = (
                    analysis['hsv_analysis']['hue_variance'] +
                    analysis['hsv_analysis']['saturation_variance'] + 
                    analysis['hsv_analysis']['value_variance']
                ) / 3
                hsv_variances.append(hsv_var)
        
        if hsv_variances:
            summary['color_stats'] = {
                'hsv_variance_mean': statistics.mean(hsv_variances),
                'hsv_variance_std': statistics.stdev(hsv_variances) if len(hsv_variances) > 1 else 0
            }
        
        return summary
    
    def _detect_outliers(self, analyses: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """이상치 자동 탐지"""
        outliers = []
        valid_analyses = {k: v for k, v in analyses.items() if 'error' not in v}
        
        if len(valid_analyses) < 3:
            return outliers
        
        # 파일 크기 이상치
        file_sizes = [(path, analysis['file_size']) for path, analysis in valid_analyses.items()]
        size_mean = statistics.mean([size for _, size in file_sizes])
        size_std = statistics.stdev([size for _, size in file_sizes]) if len(file_sizes) > 1 else 0
        
        for path, size in file_sizes:
            if size_std > 0:
                z_score = abs((size - size_mean) / size_std)
                if z_score > 2.0:  # 2 표준편차 이상
                    outliers.append({
                        'file_path': path,
                        'type': 'file_size_outlier',
                        'z_score': z_score,
                        'value': size,
                        'mean': size_mean,
                        'severity': 'high' if z_score > 3.0 else 'medium'
                    })
        
        # 정사각형 형태 이상치 (힌트 기반)
        square_files = [path for path, analysis in valid_analyses.items() if analysis['is_square']]
        non_square_files = [path for path, analysis in valid_analyses.items() if not analysis['is_square']]
        
        # 대부분이 정사각형이 아닌데 몇 개만 정사각형이면 이상치
        if len(square_files) < len(non_square_files) * 0.3 and len(square_files) > 0:
            for path in square_files:
                outliers.append({
                    'file_path': path,
                    'type': 'dimension_outlier',
                    'reason': 'square_among_non_square',
                    'severity': 'high',
                    'hint_match': True  # 힌트와 매치됨
                })
        
        # HSV 분산 이상치 (색상 분포 이상)
        hsv_data = []
        for path, analysis in valid_analyses.items():
            if 'hsv_analysis' in analysis:
                total_variance = (
                    analysis['hsv_analysis']['hue_variance'] +
                    analysis['hsv_analysis']['saturation_variance'] + 
                    analysis['hsv_analysis']['value_variance']
                )
                hsv_data.append((path, total_variance))
        
        if len(hsv_data) > 2:
            hsv_mean = statistics.mean([var for _, var in hsv_data])
            hsv_std = statistics.stdev([var for _, var in hsv_data]) if len(hsv_data) > 1 else 0
            
            for path, variance in hsv_data:
                if hsv_std > 0:
                    z_score = abs((variance - hsv_mean) / hsv_std)
                    if z_score > 1.5:  # HSV는 더 민감하게 탐지
                        outliers.append({
                            'file_path': path,
                            'type': 'color_distribution_outlier',
                            'z_score': z_score,
                            'variance': variance,
                            'severity': 'high' if z_score > 2.5 else 'medium'
                        })
        
        # 엔트로피 이상치
        entropy_data = []
        for path, analysis in valid_analyses.items():
            if 'entropy_analysis' in analysis:
                entropy_data.append((path, analysis['entropy_analysis']['total_entropy']))
        
        if len(entropy_data) > 2:
            entropy_mean = statistics.mean([ent for _, ent in entropy_data])
            entropy_std = statistics.stdev([ent for _, ent in entropy_data]) if len(entropy_data) > 1 else 0
            
            for path, entropy in entropy_data:
                if entropy_std > 0:
                    z_score = abs((entropy - entropy_mean) / entropy_std)
                    if z_score > 2.0:
                        outliers.append({
                            'file_path': path,
                            'type': 'entropy_outlier',
                            'z_score': z_score,
                            'entropy': entropy,
                            'severity': 'medium'
                        })
        
        return outliers
    
    def _detect_patterns(self, analyses: Dict[str, Dict]) -> Dict[str, Any]:
        """숨겨진 패턴 검색"""
        patterns = {
            'ascii_patterns': [],
            'hash_patterns': [],
            'dimension_patterns': [],
            'suspicious_files': []
        }
        
        valid_analyses = {k: v for k, v in analyses.items() if 'error' not in v}
        
        # ASCII 패턴 검색
        for path, analysis in valid_analyses.items():
            if 'pattern_analysis' in analysis:
                pattern_data = analysis['pattern_analysis']
                if pattern_data['text_probability'] > 0.1:  # 10% 이상 텍스트 확률
                    patterns['ascii_patterns'].append({
                        'file_path': path,
                        'text_probability': pattern_data['text_probability'],
                        'readable_sequences': pattern_data['readable_sequences'],
                        'ascii_sample': pattern_data['ascii_candidates'][:50]
                    })
        
        # 차원 패턴
        dimensions = [(path, analysis['dimensions']) for path, analysis in valid_analyses.items()]
        dimension_counter = Counter([dim for _, dim in dimensions])
        
        for (width, height), count in dimension_counter.most_common():
            if count == 1 and len(dimensions) > 5:  # 유일한 크기
                matching_files = [path for path, dim in dimensions if dim == (width, height)]
                patterns['dimension_patterns'].append({
                    'dimension': (width, height),
                    'files': matching_files,
                    'uniqueness': 'unique_size',
                    'suspicion_level': 'high'
                })
        
        # 의심스러운 파일 종합
        suspicious_indicators = {}
        
        for path, analysis in valid_analyses.items():
            suspicion_score = 0
            reasons = []
            
            # 정사각형이면 의심도 +3
            if analysis['is_square']:
                suspicion_score += 3
                reasons.append('square_dimension')
            
            # 텍스트 패턴이 있으면 의심도 +2
            if 'pattern_analysis' in analysis and analysis['pattern_analysis']['text_probability'] > 0.1:
                suspicion_score += 2
                reasons.append('ascii_pattern_detected')
            
            # HSV 분산 이상치면 의심도 +2
            if 'hsv_analysis' in analysis:
                hsv = analysis['hsv_analysis']
                if hsv.get('hue_anomaly') or hsv.get('saturation_anomaly') or hsv.get('value_anomaly'):
                    suspicion_score += 2
                    reasons.append('color_anomaly')
            
            if suspicion_score >= 3:  # 의심도 3 이상
                patterns['suspicious_files'].append({
                    'file_path': path,
                    'suspicion_score': suspicion_score,
                    'reasons': reasons,
                    'priority': 'high' if suspicion_score >= 5 else 'medium'
                })
        
        return patterns
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """분석 결과 기반 추천사항 생성"""
        recommendations = []
        
        # 이상치가 발견된 경우
        if results['outliers']:
            high_priority_outliers = [o for o in results['outliers'] if o.get('severity') == 'high']
            if high_priority_outliers:
                recommendations.append("🎯 고우선순위 이상치가 발견되었습니다. 해당 파일들을 집중 분석하세요.")
                for outlier in high_priority_outliers[:3]:  # 상위 3개만
                    filename = os.path.basename(outlier['file_path'])
                    recommendations.append(f"   → {filename}: {outlier['type']}")
        
        # 힌트와 매칭되는 패턴
        hint_matches = [o for o in results['outliers'] if o.get('hint_match')]
        if hint_matches:
            recommendations.append("💡 CTF 힌트와 일치하는 패턴이 발견되었습니다!")
        
        # ASCII 패턴 발견
        if results['patterns']['ascii_patterns']:
            recommendations.append("📝 ASCII 텍스트 패턴이 감지되었습니다. RGB 값을 문자로 변환해보세요.")
        
        # 의심스러운 파일
        suspicious = results['patterns']['suspicious_files']
        high_suspicious = [s for s in suspicious if s['priority'] == 'high']
        if high_suspicious:
            recommendations.append(f"🚨 {len(high_suspicious)}개의 매우 의심스러운 파일이 발견되었습니다.")
            for sus in high_suspicious[:2]:  # 상위 2개만
                filename = os.path.basename(sus['file_path'])
                recommendations.append(f"   → {filename} (점수: {sus['suspicion_score']})")
        
        if not recommendations:
            recommendations.append("✅ 특별한 이상치는 발견되지 않았습니다. 다른 분석 방법을 시도해보세요.")
        
        return recommendations
    
    def search_for_flags(self, analysis_result: Dict[str, Any]) -> List[str]:
        """분석 결과에서 CTF 플래그 패턴 검색"""
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}', 
            r'CTF\{[^}]+\}',
            r'ctf\{[^}]+\}'
        ]
        
        # ASCII 패턴에서 플래그 검색
        if 'patterns' in analysis_result and 'ascii_patterns' in analysis_result['patterns']:
            for pattern_data in analysis_result['patterns']['ascii_patterns']:
                # readable_sequences에서 검색
                for sequence in pattern_data.get('readable_sequences', []):
                    for flag_pattern in flag_patterns:
                        matches = re.findall(flag_pattern, sequence, re.IGNORECASE)
                        flags.extend(matches)
                
                # ascii_sample에서도 검색
                ascii_string = ''.join(pattern_data.get('ascii_sample', []))
                for flag_pattern in flag_patterns:
                    matches = re.findall(flag_pattern, ascii_string, re.IGNORECASE)
                    flags.extend(matches)
        
        return list(set(flags))  # 중복 제거


def main():
    """통계 분석 도구 테스트"""
    analyzer = StatisticalAnalyzer()
    
    # Turtles All The Way Down CTF 문제 테스트
    test_dir = "CTF-문제-사진/turtles_all_the_way_down/ctf"
    
    if os.path.exists(test_dir):
        print("🐢 Turtles All The Way Down CTF 문제 분석 시작")
        print("=" * 60)
        
        # 모든 이미지 파일 수집
        file_list = []
        for filename in os.listdir(test_dir):
            if any(filename.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.bmp']):
                file_list.append(os.path.join(test_dir, filename))
        
        file_list.sort()  # 정렬
        print(f"📁 총 {len(file_list)}개 파일 발견")
        
        # 통계 분석 실행
        result = analyzer.analyze_multiple_files(file_list)
        
        # 결과 출력
        print(f"\n📊 분석 완료: {result['file_count']}개 파일")
        
        # 이상치 출력
        if result['outliers']:
            print(f"\n🎯 이상치 {len(result['outliers'])}개 발견:")
            for outlier in result['outliers']:
                filename = os.path.basename(outlier['file_path'])
                print(f"  🚨 {filename}")
                print(f"     타입: {outlier['type']}")
                print(f"     심각도: {outlier['severity']}")
                if 'z_score' in outlier:
                    print(f"     Z-score: {outlier['z_score']:.2f}")
                if outlier.get('hint_match'):
                    print(f"     💡 힌트 매치!")
                print()
        
        # 의심스러운 파일
        suspicious = result['patterns']['suspicious_files']
        if suspicious:
            print(f"🔍 의심스러운 파일 {len(suspicious)}개:")
            for sus in suspicious:
                filename = os.path.basename(sus['file_path'])
                print(f"  🎯 {filename} (점수: {sus['suspicion_score']})")
                print(f"     이유: {', '.join(sus['reasons'])}")
                print()
        
        # 플래그 검색
        flags = analyzer.search_for_flags(result)
        if flags:
            print("🚩 발견된 플래그:")
            for flag in flags:
                print(f"  ✅ {flag}")
        else:
            print("❌ 플래그를 찾을 수 없습니다")
        
        # 추천사항
        if result['recommendations']:
            print(f"\n💡 추천사항:")
            for rec in result['recommendations']:
                print(f"  {rec}")
        
        print("\n" + "=" * 60)
    else:
        print("❌ 테스트 디렉토리를 찾을 수 없습니다")


if __name__ == "__main__":
    main()