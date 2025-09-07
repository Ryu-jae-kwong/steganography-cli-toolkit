# 채널 분석 기법

## 📖 기법 설명
RGB, RGBA, CMYK 등 이미지의 개별 색상 채널에 숨겨진 데이터를 분석하는 기법입니다.
특정 채널에서만 보이는 패턴이나 텍스트를 찾아내는 것이 목표입니다.

## 🎯 수록된 CTF 문제

### 1. Hide and Seek (난이도: Medium)
- **출처**: CSAW 2022 (250점)
- **설명**: PNG 이미지의 여러 채널에 숨겨진 데이터를 찾으세요.
- **플래그**: `flag{RGB_ch4nn3l_h1d1ng}`
- **해결방법**: RGB 채널을 분리하여 각각 분석
- **파일**: (PNG 이미지 파일이 있을 경우)

## 🛠️ 분석 도구
- **StegSolve**: 채널별 분석에 최적화된 도구
- **GIMP**: 채널 분리 및 시각적 분석
- **ImageMagick**: 명령줄 이미지 조작 도구
- **Python PIL/OpenCV**: 프로그래밍적 채널 분석

## 💡 분석 팁
1. StegSolve에서 Red, Green, Blue plane 각각 확인
2. `convert image.png -channel R -separate red.png` - ImageMagick으로 채널 분리
3. 알파 채널(투명도)도 확인 필요
4. 채널간 XOR 연산으로 숨겨진 패턴 찾기
5. 히스토그램 분석으로 채널별 데이터 분포 확인