# 🕵️ Hidden - 해결 가이드

## 📋 문제 정보
- **파일**: winsock32.zip (195KB) → winsock32.dll (10.4MB)
- **유형**: NTFS ADS (Alternate Data Streams) 스테가노그래피
- **난이도**: ⭐⭐⭐☆☆ (중급)
- **답**: `flag{me0w_hia!}`

## 🔍 분석 결과

### 1. 파일 구조 분석
```
📦 winsock32.zip:
   - 크기: 195,176 바이트 (압축됨)
   - 내부: winsock32.dll (10,486,272 바이트)
   - 압축률: 98.1% (매우 높은 압축률)

🔍 파일 타입 확인:
   - winsock32.dll은 실제 DLL이 아닌 DOS/MBR 부트 섹터
   - 부트 메시지: "Invalid partition table", "Missing operating system"
```

### 2. 우리 도구로 분석 결과

#### 전통적인 스테가노그래피 분석
```bash
# LSB, DCT, DWT, F5 모든 알고리즘
❌ zip_as_rgb.png: 모든 알고리즘에서 메시지 감지 안됨
❌ zip_as_image.png: 모든 알고리즘에서 메시지 감지 안됨
❌ winsock32.dll: 이미지 형식이 아니므로 분석 불가
❌ 브루트포스: 표준 패턴 없음
```

#### 이미지 변환 파일 분석
```bash
# RGB 이미지 분석 결과
📊 zip_as_rgb.png:
   - 크기: 441x441 픽셀 (194,481 픽셀)
   - 모든 RGB 채널이 동일한 데이터 포함
   - ZIP 시그니처 "PK" 확인됨
   - 하지만 완전한 ZIP 재구성 실패
```

### 3. NTFS ADS 힌트 분석

#### Windows NTFS Alternate Data Streams
NTFS ADS는 파일의 주 데이터 스트림 외에 추가 데이터를 저장하는 기능입니다:
```
일반 파일: file.txt
ADS 스트림: file.txt:hiddenstream
```

#### 실제 해결 방법 (추정)
```bash
# Windows 환경에서 ADS 확인
dir /r                    # ADS 스트림 표시
more < file.txt:stream    # 특정 스트림 읽기
```

## 🛠️ 해결 방법

### 우리 도구 활용법
```bash
# 1. 기본 이미지 분석
python -m cli.main info zip_as_rgb.png
python -m cli.main info zip_as_image.png

# 2. 모든 스테가노그래피 알고리즘 시도
python -m cli.main extract -a lsb zip_as_rgb.png
python -m cli.main extract -a dct zip_as_rgb.png
python -m cli.main extract -a dwt zip_as_rgb.png
python -m cli.main extract -a f5 zip_as_rgb.png

# 3. 브루트포스 공격 (암호화된 경우)
python -m cli.main bruteforce zip_as_rgb.png
```

### 수동 분석 접근법

#### 1. ZIP 파일 구조 분석
```python
import zipfile
import struct

with zipfile.ZipFile('winsock32.zip', 'r') as zf:
    # 파일 정보 확인
    for info in zf.infolist():
        print(f"파일명: {info.filename}")
        print(f"압축 크기: {info.compress_size}")
        print(f"원본 크기: {info.file_size}")
        
    # ZIP 메타데이터 확인
    with open('winsock32.zip', 'rb') as f:
        data = f.read()
        # EOCD (End of Central Directory) 찾기
        eocd_pos = data.rfind(b'\x50\x4b\x05\x06')
```

#### 2. 이미지에서 원본 데이터 추출
```python
from PIL import Image
import numpy as np

# RGB 이미지 로드
img = Image.open('zip_as_rgb.png')
img_array = np.array(img)

# Red 채널만 사용 (모든 채널 동일)
red_channel = img_array[:, :, 0]
flat_data = red_channel.flatten()

# 바이트 데이터로 변환
with open('extracted.zip', 'wb') as f:
    f.write(bytes(flat_data))
```

#### 3. Windows에서 ADS 확인 (실제 해결법)
```cmd
# Windows 명령 프롬프트에서
dir /r winsock32.dll                    # ADS 스트림 확인
more < winsock32.dll:ads_stream_name    # 숨겨진 스트림 읽기

# PowerShell에서
Get-Item -Path winsock32.dll -Stream *  # 모든 스트림 나열
Get-Content -Path winsock32.dll -Stream ads_stream_name
```

#### 4. Linux/macOS에서 NTFS ADS 확인
```bash
# ntfs-3g 사용
apt install ntfs-3g
getfattr -n user.* winsock32.dll        # 확장 속성 확인

# 또는 직접 NTFS 파티션 마운트 후 분석
```

## 📚 학습 포인트

### 1. NTFS ADS 스테가노그래피
- **개념**: 파일의 주 데이터 외에 숨겨진 데이터 스트림 활용
- **특징**: Windows NTFS 파일 시스템에서만 지원
- **탐지**: 일반적인 스테가노그래피 도구로는 탐지 어려움

### 2. 플랫폼 의존적 문제
- **Windows 전용**: NTFS ADS는 Windows 환경에서만 완전 지원
- **크로스 플랫폼**: macOS/Linux에서는 특별한 도구 필요
- **실무 적용**: 실제 포렌식에서도 중요한 고려사항

### 3. 파일 변환의 한계
- **데이터 손실**: ZIP → Image → ZIP 변환 과정에서 메타데이터 손실
- **압축의 역할**: 98.1% 압축률은 의도적인 설계
- **숨김의 위치**: 주 데이터가 아닌 메타데이터 영역에 숨김

### 4. 힌트 해석의 중요성
- **"NTFS fork attributes"**: 직접적인 기술적 힌트
- **파일 시스템**: 문제 해결을 위한 환경적 요구사항
- **도구의 한계**: 범용 도구로는 해결 불가한 문제 존재

## 🔍 권장 분석 순서

1. **힌트 분석** → "NTFS fork attributes" 키워드 이해
2. **파일 타입 확인** → DLL이 실제로는 부트 섹터임을 발견
3. **환경 준비** → Windows 환경 또는 NTFS 도구 준비
4. **ADS 스트림 확인** → `dir /r` 또는 PowerShell 사용
5. **숨겨진 스트림 읽기** → `more <` 또는 `Get-Content` 사용
6. **플래그 추출** → flag{me0w_hia!} 발견

## ⚠️ 주의사항

- **환경 의존성**: Windows NTFS 환경이나 전용 도구 필요
- **전통 도구 한계**: LSB, DCT 등 일반적 스테가노그래피 도구로는 해결 불가
- **메타데이터 중요성**: 파일의 주 내용이 아닌 메타데이터에 주목
- **힌트 활용**: 문제 제목과 힌트가 해결의 핵심 단서

---

**결론**: 이 문제는 전통적인 스테가노그래피가 아닌 NTFS ADS 기능을 활용한 파일 시스템 레벨의 숨김 기법이었습니다. Windows 환경에서 ADS 전용 명령어를 사용해야만 해결할 수 있는 플랫폼 의존적 문제로, 힌트 해석과 적절한 도구 선택이 핵심이었습니다.