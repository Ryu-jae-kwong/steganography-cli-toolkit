# LSB (Least Significant Bit) 기법

## 📖 기법 설명
LSB 기법은 이미지의 최하위 비트를 조작하여 데이터를 숨기는 스테가노그래피 기법입니다.
육안으로는 거의 구별할 수 없지만 디지털적으로는 정보가 숨겨져 있습니다.

## 🎯 수록된 CTF 문제

### 📁 실제 파일 포함 문제

#### 1. 🧱 Hit a Brick Wall (난이도: Medium)
- **파일 경로**: `hit_a_brick_wall/`
- **주요 파일**: `bricks.png`, `README.txt`, `문제설명.md`
- **설명**: 벽돌 이미지에 숨겨진 플래그 찾기
- **힌트**: "spare key is usually under the doormat, a plant pot, or a rock"
- **분석 도구**: StegSolve, zsteg, LSB 추출 스크립트

#### 2. 🐢 Turtles All The Way Down (난이도: Hard)
- **파일 경로**: `turtles_all_the_way_down/`
- **주요 파일**: `01.jpg~20.png` (20개 거북이 이미지), `README.txt`, `문제설명.md`
- **설명**: 행복한 거북이 사진 아카이브에서 플래그 찾기
- **힌트**: "happy" 키워드, 정사각형 이미지에 주목
- **분석 기법**: 통계적 이상치 탐지, ASCII 변환, 다중 이미지 LSB 분석

### 📋 메타데이터 기반 문제 목록

#### 3. Matryoshka doll (난이도: Medium)
- **출처**: picoCTF 2021 (30점)
- **설명**: 러시아 인형처럼 중첩된 이미지에서 플래그를 찾으세요.
- **플래그**: `picoCTF{4cf7ac000c3fb0fa96fb92722ffb2a32}`
- **해결방법**: binwalk로 숨겨진 파일 추출 후 LSB 분석

#### 4. Invisible Ink (난이도: Easy)
- **출처**: DEFCON 2023 (100점)
- **설명**: 이미지에 보이지 않는 워터마크가 숨겨져 있습니다.
- **플래그**: `DEFCON{1nv1s1bl3_w4t3rm4rk}`
- **해결방법**: LSB 분석으로 숨겨진 텍스트 추출

## 🛠️ 분석 도구
- **StegSolve**: LSB 분석에 특화된 GUI 도구
- **zsteg**: Ruby 기반 LSB 스테가노그래피 탐지 도구
- **binwalk**: 파일 내 숨겨진 데이터 탐지
- **자체 개발 도구**: `core/lsb.py` 사용

## 💡 분석 팁
1. 이미지를 StegSolve에서 열고 각 비트플레인을 확인
2. zsteg 명령어로 자동 분석
3. LSB 패턴이 의심되면 직접 비트 추출
4. 텍스트, 이미지, 또는 다른 파일이 숨겨져 있을 수 있음