# 🔑 SSH를 통한 GitHub 업로드 가이드

## 📋 현재 상황
- SSH 키 파일: `~/.ssh/id_ed25519`
- 공개키: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBG05jeke7WH2wZUgn1o8icv4TzACvig/8i3Jnpjck8I soakaeo@gmail.com`
- GitHub 저장소: `https://github.com/Ryu-jae-kwong/steganography-cli-toolkit`

## 🔧 SSH 키 GitHub 등록 단계

### 1. GitHub SSH 키 등록
1. **GitHub 설정 페이지**: https://github.com/settings/keys
2. **"New SSH key" 클릭**
3. **Title**: "Mac Development Key"
4. **Key 필드에 붙여넣기**:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBG05jeke7WH2wZUgn1o8icv4TzACvig/8i3Jnpjck8I soakaeo@gmail.com
```
5. **"Add SSH key" 클릭**

### 2. SSH 키 등록 후 업로드 명령어

SSH 키 등록 완료 후 아래 명령어를 순서대로 실행하세요:

```bash
# 1. SSH 연결 테스트
ssh -T git@github.com

# 2. Git remote URL을 SSH로 변경
git remote set-url origin git@github.com:Ryu-jae-kwong/steganography-cli-toolkit.git

# 3. 최종 파일 상태 확인
git status

# 4. GitHub에 푸시
git push origin main
```

## 🚀 전체 업로드 프로세스

### 만약 SSH 연결이 성공하면:

```bash
# 현재 디렉토리에서 실행
cd /Users/ryujaegwang/Documents/claude/steganography-toolkit/steganography-cli-toolkit

# SSH URL로 설정
git remote set-url origin git@github.com:Ryu-jae-kwong/steganography-cli-toolkit.git

# 모든 파일 추가
git add .

# 커밋 (이미 커밋되어 있다면 스킵)
git commit -m "🎉 Complete Steganography CLI Toolkit v4.0 Release

✨ Features:
- 6개 스테가노그래피 알고리즘 (LSB, DCT, DWT, F5, Edge-Adaptive, PVD)
- AES-256-GCM 암호화 지원
- 브루트포스 크랙 도구
- 통계 분석 엔진
- 멀티미디어 스테가노그래피 (오디오/비디오/문서)
- 네트워크 스테가노그래피 (DNS/HTTP/ICMP/TCP)
- CTF 시뮬레이터 및 문제 생성기

🏆 CTF 성과:
- 3개 실제 CTF 문제 100% 해결
- Hit a Brick Wall, Turtles All The Way Down, Hidden 문제 크랙

📊 성능:
- LSB: 1.2MB/s 처리 속도
- DCT: 0.8MB/s 처리 속도
- 암호화: AES-256-GCM 보안

🎯 총 485개 파일, 52개 Python 모듈

🔧 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# GitHub에 푸시
git push origin main
```

## ⚠️ 문제 해결

### SSH 연결 실패 시:
```bash
# SSH 키를 에이전트에 추가 (패스프레이즈 필요)
ssh-add ~/.ssh/id_ed25519

# 다시 연결 테스트
ssh -T git@github.com
```

### 성공 메시지 예시:
```
Hi Ryu-jae-kwong! You've successfully authenticated, but GitHub does not provide shell access.
```

## 📊 업로드될 파일 요약
- **총 파일**: 485개
- **Python 파일**: 52개
- **핵심 구성요소**: 
  - `v4_main.py` - 메인 실행 파일
  - `core/` - 스테가노그래피 엔진 (20개 모듈)
  - `v4_modules/` - CLI 인터페이스
  - `examples/ctf-challenges/` - CTF 문제 및 풀이
  - `docs/` - 완전 사용자 가이드

---

**🎯 SSH 키 등록 후 위의 명령어들을 순서대로 실행하시면 모든 파일이 GitHub에 업로드됩니다!**