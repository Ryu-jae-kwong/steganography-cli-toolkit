"""
CTF 문제 생성기 v3.0

교육용 스테가노그래피 문제를 자동으로 생성하는 시스템입니다.
다양한 난이도와 기법의 문제를 체계적으로 생성하여
실무 훈련과 교육에 활용할 수 있는 35개의 커스텀 문제를 제작합니다.
"""

import os
import random
import string
import hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from PIL import Image, ImageDraw, ImageFont
import numpy as np
from datetime import datetime
import json
import secrets

from .problem_manager import CTFProblem
from .difficulty_classifier import DifficultyClassifier, Difficulty

@dataclass
class ProblemTemplate:
    """문제 템플릿 정의"""
    category: str
    technique: str
    difficulty: str
    description_template: str
    solution_template: str
    file_generator: str  # 파일 생성 함수명
    flag_pattern: str
    estimated_points: int
    tags: List[str]

class CTFProblemGenerator:
    """교육용 CTF 문제 자동 생성기"""
    
    def __init__(self, output_dir: str = None):
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), "generated_problems")
        
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.difficulty_classifier = DifficultyClassifier()
        self.generated_problems = []
        
        # 문제 템플릿 정의
        self.templates = self._define_templates()
        
        # 플래그 접두사
        self.flag_prefixes = [
            'STEGO{', 'FLAG{', 'FORENSICS{', 'HIDDEN{', 'SECRET{', 'DIGITAL{'
        ]
        
        # 더미 데이터 생성용
        self.lorem_ipsum = [
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco.",
            "Duis aute irure dolor in reprehenderit in voluptate velit esse.",
            "Excepteur sint occaecat cupidatat non proident, sunt in culpa."
        ]
        
        # 색상 팔레트
        self.colors = [
            (255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0),
            (255, 0, 255), (0, 255, 255), (128, 128, 128), (255, 165, 0)
        ]
    
    def _define_templates(self) -> List[ProblemTemplate]:
        """문제 템플릿들을 정의합니다."""
        return [
            # Easy 레벨 문제들 (10개)
            ProblemTemplate(
                category="steganography",
                technique="metadata",
                difficulty="Easy",
                description_template="이미지 파일의 메타데이터에 플래그가 숨겨져 있습니다. EXIF 데이터를 확인하세요.",
                solution_template="exiftool {filename} 또는 이미지 속성에서 플래그 확인",
                file_generator="generate_metadata_problem",
                flag_pattern="STEGO{{metadata_{random}}}",
                estimated_points=50,
                tags=["beginner", "metadata", "exif"]
            ),
            ProblemTemplate(
                category="steganography", 
                technique="strings",
                difficulty="Easy",
                description_template="이미지 파일에 텍스트 문자열이 숨겨져 있습니다. strings 명령어를 사용하세요.",
                solution_template="strings {filename} | grep -i flag",
                file_generator="generate_strings_problem",
                flag_pattern="STEGO{{strings_{random}}}",
                estimated_points=50,
                tags=["beginner", "strings", "text"]
            ),
            ProblemTemplate(
                category="steganography",
                technique="basic_lsb",
                difficulty="Easy", 
                description_template="간단한 LSB 스테가노그래피가 적용된 이미지입니다. 기본 도구로 추출하세요.",
                solution_template="stegsolve 또는 zsteg를 사용하여 LSB 평면 확인",
                file_generator="generate_basic_lsb_problem",
                flag_pattern="STEGO{{lsb_basic_{random}}}",
                estimated_points=75,
                tags=["lsb", "steganography", "basic"]
            ),
            
            # Medium 레벨 문제들 (15개)
            ProblemTemplate(
                category="steganography",
                technique="lsb_advanced",
                difficulty="Medium",
                description_template="고급 LSB 기법이 사용된 이미지입니다. 특정 채널과 비트 평면을 분석하세요.",
                solution_template="Python 스크립트로 특정 RGB 채널의 LSB 추출",
                file_generator="generate_advanced_lsb_problem",
                flag_pattern="STEGO{{lsb_advanced_{random}}}",
                estimated_points=150,
                tags=["lsb", "advanced", "rgb_channels"]
            ),
            ProblemTemplate(
                category="steganography",
                technique="image_layers",
                difficulty="Medium",
                description_template="이미지의 여러 레이어에 정보가 분산되어 숨겨져 있습니다.",
                solution_template="이미지 레이어 분리 및 XOR 연산으로 플래그 복원",
                file_generator="generate_layer_problem",
                flag_pattern="STEGO{{layers_{random}}}",
                estimated_points=200,
                tags=["layers", "xor", "image_processing"]
            ),
            ProblemTemplate(
                category="steganography",
                technique="qr_hidden",
                difficulty="Medium",
                description_template="이미지에 QR 코드가 숨겨져 있습니다. 노이즈를 제거하고 QR 코드를 복원하세요.",
                solution_template="이미지 필터링으로 QR 코드 노출 후 디코딩",
                file_generator="generate_qr_problem",
                flag_pattern="STEGO{{qr_code_{random}}}",
                estimated_points=180,
                tags=["qr_code", "image_filtering", "decode"]
            ),
            
            # Hard 레벨 문제들 (8개)
            ProblemTemplate(
                category="steganography",
                technique="frequency_domain",
                difficulty="Hard",
                description_template="주파수 도메인에 데이터가 숨겨진 이미지입니다. DCT 또는 DFT 분석이 필요합니다.",
                solution_template="FFT 변환 또는 DCT 계수 분석으로 숨겨진 패턴 발견",
                file_generator="generate_frequency_problem",
                flag_pattern="STEGO{{frequency_{random}}}",
                estimated_points=300,
                tags=["frequency", "dct", "fft", "signal_processing"]
            ),
            ProblemTemplate(
                category="steganography",
                technique="polyglot_file",
                difficulty="Hard",
                description_template="하나의 파일이 동시에 여러 형식으로 해석됩니다. 각 형식에서 정보 조각을 찾으세요.",
                solution_template="파일을 PNG, ZIP, PDF로 각각 해석하여 정보 수집",
                file_generator="generate_polyglot_problem",
                flag_pattern="STEGO{{polyglot_{random}}}",
                estimated_points=400,
                tags=["polyglot", "file_format", "forensics"]
            ),
            
            # Expert 레벨 문제들 (2개)
            ProblemTemplate(
                category="steganography",
                technique="custom_cipher",
                difficulty="Expert",
                description_template="커스텀 암호화와 스테가노그래피가 결합된 문제입니다. 알고리즘을 역분석하세요.",
                solution_template="알고리즘 분석 후 커스텀 디코더 구현 필요",
                file_generator="generate_custom_cipher_problem",
                flag_pattern="STEGO{{custom_cipher_{random}}}",
                estimated_points=600,
                tags=["expert", "custom_algorithm", "crypto", "reverse_engineering"]
            )
        ]
    
    def generate_problem_set(self, target_count: int = 35) -> List[CTFProblem]:
        """목표 개수만큼 문제 세트를 생성합니다."""
        print(f"🎯 {target_count}개 교육용 문제 생성 시작...")
        
        # 난이도별 분배 (이상적인 비율)
        distribution = {
            'Easy': int(target_count * 0.3),      # 30% - 약 10개
            'Medium': int(target_count * 0.4),    # 40% - 약 14개 
            'Hard': int(target_count * 0.25),     # 25% - 약 9개
            'Expert': target_count - int(target_count * 0.95)  # 5% - 약 2개
        }
        
        generated_problems = []
        
        for difficulty, count in distribution.items():
            difficulty_templates = [t for t in self.templates if t.difficulty == difficulty]
            
            for i in range(count):
                template = random.choice(difficulty_templates)
                problem = self._generate_single_problem(template, i)
                if problem:
                    generated_problems.append(problem)
                    print(f"✅ {difficulty} 문제 생성: '{problem.title}' (ID: {problem.id})")
        
        self.generated_problems = generated_problems
        print(f"🎉 총 {len(generated_problems)}개 문제 생성 완료!")
        
        return generated_problems
    
    def _generate_single_problem(self, template: ProblemTemplate, index: int) -> Optional[CTFProblem]:
        """템플릿을 기반으로 단일 문제를 생성합니다."""
        try:
            # 랜덤 요소 생성
            random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            
            # 플래그 생성
            flag = template.flag_pattern.format(random=random_str)
            
            # 문제 제목 생성
            title = f"{template.difficulty} {template.technique.title()} Challenge #{index+1:02d}"
            
            # 문제 ID 생성
            problem_id = hashlib.sha256(
                f"{title}_{template.technique}_{datetime.now().isoformat()}".encode()
            ).hexdigest()[:12]
            
            # 파일 생성
            filename = f"{problem_id}_{template.technique}.png"
            file_path = os.path.join(self.output_dir, filename)
            
            # 파일 생성 함수 호출
            file_generator = getattr(self, template.file_generator, None)
            if file_generator:
                success = file_generator(file_path, flag, template)
                if not success:
                    print(f"❌ 파일 생성 실패: {template.file_generator}")
                    return None
            else:
                print(f"⚠️ 파일 생성기 없음: {template.file_generator}")
                # 기본 이미지 생성
                self._generate_default_image(file_path, flag)
            
            # 문제 객체 생성
            problem = CTFProblem(
                id=problem_id,
                title=title,
                description=template.description_template,
                category=template.category,
                technique=template.technique,
                difficulty=template.difficulty,
                source="custom_generated",
                year=datetime.now().year,
                points=template.estimated_points,
                files=[file_path],
                flag=flag,
                solution=template.solution_template.format(filename=filename),
                tags=template.tags + ["generated", "educational"]
            )
            
            return problem
            
        except Exception as e:
            print(f"❌ 문제 생성 실패: {e}")
            return None
    
    def generate_metadata_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """메타데이터 문제 파일을 생성합니다."""
        try:
            # 기본 이미지 생성
            img = Image.new('RGB', (400, 300), (200, 200, 200))
            draw = ImageDraw.Draw(img)
            
            # 더미 내용 그리기
            draw.text((20, 20), "Digital Forensics Training", fill=(0, 0, 0))
            draw.text((20, 50), "Find the hidden flag!", fill=(0, 0, 0))
            draw.rectangle([20, 100, 380, 200], outline=(100, 100, 100), width=2)
            
            # EXIF 데이터에 플래그 삽입
            from PIL.ExifTags import TAGS
            from PIL import ExifTags
            
            # 임시로 저장 후 exif 데이터 조작
            img.save(file_path)
            
            # piexif 라이브러리가 있다면 사용, 없으면 기본 방식
            try:
                import piexif
                
                exif_dict = {
                    "0th": {
                        piexif.ImageIFD.Artist: flag,
                        piexif.ImageIFD.ImageDescription: "Steganography Training Image",
                        piexif.ImageIFD.Copyright: "Digital Forensics Lab 2024"
                    },
                    "Exif": {
                        piexif.ExifIFD.UserComment: flag.encode()
                    }
                }
                
                exif_bytes = piexif.dump(exif_dict)
                img.save(file_path, exif=exif_bytes)
                
            except ImportError:
                # piexif가 없으면 파일명에 힌트 추가
                print("ℹ️ piexif 라이브러리가 없어 기본 방식으로 생성됩니다.")
                
                # 이미지에 텍스트로 힌트 추가
                draw.text((20, 250), f"Hint: Check metadata for {flag[:10]}...", fill=(100, 100, 100))
                img.save(file_path)
            
            return True
            
        except Exception as e:
            print(f"메타데이터 문제 생성 오류: {e}")
            return False
    
    def generate_strings_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """strings 문제 파일을 생성합니다."""
        try:
            # 기본 이미지 생성
            img = Image.new('RGB', (500, 400), (220, 220, 255))
            draw = ImageDraw.Draw(img)
            
            # 시각적 내용
            draw.text((20, 20), "String Analysis Challenge", fill=(0, 0, 100))
            for i in range(5):
                y = 80 + i * 40
                draw.text((20, y), f"Line {i+1}: {self.lorem_ipsum[i][:40]}...", fill=(50, 50, 50))
            
            img.save(file_path)
            
            # 파일 끝에 텍스트 데이터 추가
            with open(file_path, 'ab') as f:
                # 더미 문자열들 추가
                dummy_strings = [
                    b"This is not the flag you are looking for\n",
                    b"Keep searching for the real flag\n", 
                    b"Decoy flag: FAKE{not_real_flag}\n",
                    b"Random data: " + secrets.token_bytes(20) + b"\n",
                    flag.encode() + b"\n",  # 실제 플래그
                    b"More dummy data after the flag\n",
                    b"End of hidden strings\n"
                ]
                
                # 랜덤하게 섞어서 추가
                random.shuffle(dummy_strings)
                for s in dummy_strings:
                    f.write(s)
            
            return True
            
        except Exception as e:
            print(f"strings 문제 생성 오류: {e}")
            return False
    
    def generate_basic_lsb_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """기본 LSB 문제 파일을 생성합니다."""
        try:
            # 512x512 이미지 생성
            width, height = 512, 512
            img = Image.new('RGB', (width, height))
            pixels = list(img.getdata())
            
            # 플래그를 바이너리로 변환
            flag_binary = ''.join(format(ord(c), '08b') for c in flag)
            flag_binary += '1111111111111110'  # 종료 마커
            
            # LSB에 데이터 삽입
            pixel_index = 0
            bit_index = 0
            
            for bit in flag_binary:
                if pixel_index >= len(pixels):
                    break
                    
                r, g, b = pixels[pixel_index]
                
                # Red 채널의 LSB에 삽입
                if bit_index % 3 == 0:
                    r = (r & 0xFE) | int(bit)
                elif bit_index % 3 == 1:
                    g = (g & 0xFE) | int(bit)
                else:
                    b = (b & 0xFE) | int(bit)
                    pixel_index += 1
                
                pixels[pixel_index if pixel_index < len(pixels) else len(pixels)-1] = (r, g, b)
                bit_index += 1
            
            # 나머지 픽셀을 랜덤 색상으로 채움
            for i in range(pixel_index, len(pixels)):
                if i >= len(pixels):
                    break
                pixels[i] = (
                    random.randint(0, 255),
                    random.randint(0, 255), 
                    random.randint(0, 255)
                )
            
            # 이미지 저장
            img.putdata(pixels[:len(pixels)])
            img.save(file_path)
            
            return True
            
        except Exception as e:
            print(f"기본 LSB 문제 생성 오류: {e}")
            return False
    
    def generate_advanced_lsb_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """고급 LSB 문제 파일을 생성합니다."""
        try:
            # 복잡한 패턴의 이미지 생성
            width, height = 800, 600
            img = Image.new('RGB', (width, height))
            
            # 그라데이션 배경 생성
            pixels = []
            for y in range(height):
                for x in range(width):
                    r = int(255 * x / width)
                    g = int(255 * y / height)
                    b = int(255 * (x + y) / (width + height))
                    pixels.append((r, g, b))
            
            # 플래그를 특별한 패턴으로 인코딩
            flag_binary = ''.join(format(ord(c), '08b') for c in flag)
            
            # Green 채널의 LSB에만 삽입 (고급 기법)
            for i, bit in enumerate(flag_binary):
                if i >= len(pixels):
                    break
                
                r, g, b = pixels[i]
                g = (g & 0xFE) | int(bit)  # Green 채널 LSB만 수정
                pixels[i] = (r, g, b)
            
            img.putdata(pixels)
            img.save(file_path)
            
            return True
            
        except Exception as e:
            print(f"고급 LSB 문제 생성 오류: {e}")
            return False
    
    def generate_layer_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """레이어 문제 파일을 생성합니다."""
        try:
            width, height = 600, 400
            
            # 3개 레이어 생성
            layer1 = Image.new('RGB', (width, height), (200, 100, 100))
            layer2 = Image.new('RGB', (width, height), (100, 200, 100))
            layer3 = Image.new('RGB', (width, height), (100, 100, 200))
            
            # 플래그를 3개 레이어로 분할
            flag_bytes = flag.encode()
            part_size = len(flag_bytes) // 3 + 1
            
            parts = [
                flag_bytes[:part_size],
                flag_bytes[part_size:part_size*2], 
                flag_bytes[part_size*2:]
            ]
            
            layers = [layer1, layer2, layer3]
            
            # 각 레이어에 데이터 삽입
            for layer_idx, (layer, part) in enumerate(zip(layers, parts)):
                pixels = list(layer.getdata())
                
                for byte_idx, byte_val in enumerate(part):
                    if byte_idx >= len(pixels):
                        break
                    
                    r, g, b = pixels[byte_idx]
                    
                    # 각 레이어는 다른 채널에 삽입
                    if layer_idx == 0:  # Red 레이어
                        r = byte_val
                    elif layer_idx == 1:  # Green 레이어
                        g = byte_val
                    else:  # Blue 레이어
                        b = byte_val
                    
                    pixels[byte_idx] = (r, g, b)
                
                layer.putdata(pixels)
            
            # 레이어들을 블렌딩하여 최종 이미지 생성
            result = Image.blend(layer1, layer2, 0.5)
            result = Image.blend(result, layer3, 0.33)
            
            result.save(file_path)
            
            return True
            
        except Exception as e:
            print(f"레이어 문제 생성 오류: {e}")
            return False
    
    def generate_qr_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """QR 코드 문제 파일을 생성합니다."""
        try:
            # QR 코드 생성
            try:
                import qrcode
                
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(flag)
                qr.make(fit=True)
                
                qr_img = qr.make_image(fill_color="black", back_color="white")
                
                # 노이즈가 있는 배경 이미지 생성
                width, height = 800, 600
                background = Image.new('RGB', (width, height))
                
                # 랜덤 노이즈 추가
                pixels = []
                for y in range(height):
                    for x in range(width):
                        noise = random.randint(-50, 50)
                        base_color = 128 + noise
                        base_color = max(0, min(255, base_color))
                        pixels.append((base_color, base_color, base_color))
                
                background.putdata(pixels)
                
                # QR 코드를 배경에 블렌딩 (거의 보이지 않게)
                qr_resized = qr_img.resize((200, 200))
                
                # QR 코드를 배경에 매우 약하게 합성
                paste_x = (width - 200) // 2
                paste_y = (height - 200) // 2
                
                # 알파 블렌딩으로 QR 코드를 희미하게 삽입
                qr_array = np.array(qr_resized)
                bg_array = np.array(background)
                
                for y in range(200):
                    for x in range(200):
                        bg_y = paste_y + y
                        bg_x = paste_x + x
                        
                        if bg_y < height and bg_x < width:
                            if qr_array[y, x] == 0:  # 검은색 QR 부분
                                # 매우 약한 차이로 변경
                                bg_array[bg_y, bg_x] = [
                                    max(0, bg_array[bg_y, bg_x][0] - 30),
                                    max(0, bg_array[bg_y, bg_x][1] - 30),
                                    max(0, bg_array[bg_y, bg_x][2] - 30)
                                ]
                
                result = Image.fromarray(bg_array)
                result.save(file_path)
                
                return True
                
            except ImportError:
                print("ℹ️ qrcode 라이브러리가 없어 기본 패턴으로 생성됩니다.")
                # QR 코드 없이 기본 이미지 생성
                self._generate_default_image(file_path, flag)
                return True
                
        except Exception as e:
            print(f"QR 문제 생성 오류: {e}")
            return False
    
    def generate_frequency_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """주파수 도메인 문제 파일을 생성합니다."""
        try:
            # 복잡한 신호가 포함된 이미지 생성
            width, height = 512, 512
            
            # 기본 이미지 (자연스러운 패턴)
            img_array = np.zeros((height, width, 3))
            
            # 사인파 패턴으로 기본 이미지 생성
            for y in range(height):
                for x in range(width):
                    r = int(127 + 127 * np.sin(2 * np.pi * x / 64))
                    g = int(127 + 127 * np.sin(2 * np.pi * y / 64))
                    b = int(127 + 127 * np.sin(2 * np.pi * (x + y) / 128))
                    img_array[y, x] = [r, g, b]
            
            # 플래그를 주파수 도메인에 삽입
            flag_binary = ''.join(format(ord(c), '08b') for c in flag)
            
            # DCT 계수에 플래그 정보 삽입 (시뮬레이션)
            for i, bit in enumerate(flag_binary[:100]):  # 처음 100비트만
                freq_x = 10 + i % 50
                freq_y = 10 + i // 50
                
                if freq_x < width and freq_y < height:
                    # 특정 주파수 성분 조작
                    if int(bit):
                        img_array[freq_y, freq_x] = [255, 255, 255]  # 강한 신호
                    else:
                        img_array[freq_y, freq_x] = [0, 0, 0]  # 약한 신호
            
            # 이미지 저장
            img = Image.fromarray(img_array.astype(np.uint8))
            img.save(file_path)
            
            return True
            
        except Exception as e:
            print(f"주파수 문제 생성 오류: {e}")
            return False
    
    def generate_polyglot_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """폴리글랏 파일 문제를 생성합니다."""
        try:
            # PNG 이미지 기본 생성
            img = Image.new('RGB', (400, 300), (150, 150, 200))
            draw = ImageDraw.Draw(img)
            draw.text((20, 20), "Polyglot File Challenge", fill=(255, 255, 255))
            draw.text((20, 50), "This file has multiple formats!", fill=(255, 255, 255))
            
            img.save(file_path)
            
            # 파일 끝에 ZIP 데이터 추가
            import zipfile
            import io
            
            # 메모리에서 ZIP 파일 생성
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zipf:
                zipf.writestr('flag.txt', flag)
                zipf.writestr('readme.txt', 'This is hidden in the polyglot file!')
            
            zip_data = zip_buffer.getvalue()
            
            # PNG 파일 끝에 ZIP 데이터 추가
            with open(file_path, 'ab') as f:
                f.write(zip_data)
            
            return True
            
        except Exception as e:
            print(f"폴리글랏 문제 생성 오류: {e}")
            return False
    
    def generate_custom_cipher_problem(self, file_path: str, flag: str, template: ProblemTemplate) -> bool:
        """커스텀 암호화 문제 파일을 생성합니다."""
        try:
            # 복잡한 패턴의 이미지 생성
            width, height = 1024, 768
            img = Image.new('RGB', (width, height))
            
            # 커스텀 암호화 알고리즘: XOR + 시저 암호 + 비트 회전
            def custom_encrypt(data: str, key: int) -> bytes:
                encrypted = []
                for i, char in enumerate(data):
                    # XOR with position-dependent key
                    step1 = ord(char) ^ ((key + i) % 256)
                    # Caesar cipher shift
                    step2 = (step1 + key) % 256
                    # Bit rotation
                    step3 = ((step2 << 3) | (step2 >> 5)) & 0xFF
                    encrypted.append(step3)
                return bytes(encrypted)
            
            # 플래그를 커스텀 암호화
            encryption_key = 42  # 고정 키 (분석 가능하도록)
            encrypted_flag = custom_encrypt(flag, encryption_key)
            
            # 암호화된 데이터를 이미지에 임베딩
            pixels = []
            data_index = 0
            
            for y in range(height):
                for x in range(width):
                    # 기본 패턴 생성
                    r = (x * 31 + y * 17) % 256
                    g = (x * 23 + y * 29) % 256
                    b = (x * 19 + y * 37) % 256
                    
                    # 암호화된 데이터 임베딩
                    if data_index < len(encrypted_flag):
                        # 3개 채널에 데이터 분산
                        encrypted_byte = encrypted_flag[data_index]
                        r = (r & 0xFC) | ((encrypted_byte >> 6) & 0x03)
                        g = (g & 0xFC) | ((encrypted_byte >> 4) & 0x03)
                        b = (b & 0xFC) | ((encrypted_byte >> 2) & 0x03)
                        data_index += 1
                    
                    pixels.append((r, g, b))
            
            img.putdata(pixels)
            
            # 힌트 이미지에 추가
            draw = ImageDraw.Draw(img)
            draw.text((20, 20), f"Cipher Key Hint: {encryption_key}", fill=(255, 255, 255))
            draw.text((20, 50), "Algorithm: XOR + Caesar + BitRotate", fill=(255, 255, 255))
            
            img.save(file_path)
            
            return True
            
        except Exception as e:
            print(f"커스텀 암호화 문제 생성 오류: {e}")
            return False
    
    def _generate_default_image(self, file_path: str, flag: str):
        """기본 이미지를 생성합니다."""
        img = Image.new('RGB', (400, 300), random.choice(self.colors))
        draw = ImageDraw.Draw(img)
        
        draw.text((20, 20), "Steganography Challenge", fill=(255, 255, 255))
        draw.text((20, 50), f"Find the hidden: {flag[:10]}...", fill=(200, 200, 200))
        draw.rectangle([20, 100, 380, 280], outline=(255, 255, 255), width=3)
        
        img.save(file_path)
    
    def export_problem_set(self, problems: List[CTFProblem], output_file: str = None) -> str:
        """생성된 문제 세트를 내보냅니다."""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"custom_problems_{timestamp}.json"
        
        export_data = {
            'metadata': {
                'generation_date': datetime.now().isoformat(),
                'total_problems': len(problems),
                'generator_version': '3.0.0',
                'difficulty_distribution': self._get_difficulty_stats(problems)
            },
            'problems': [
                {
                    'id': p.id,
                    'title': p.title,
                    'description': p.description,
                    'category': p.category,
                    'technique': p.technique,
                    'difficulty': p.difficulty,
                    'source': p.source,
                    'year': p.year,
                    'points': p.points,
                    'files': p.files,
                    'flag': p.flag,
                    'solution': p.solution,
                    'tags': p.tags
                }
                for p in problems
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        
        print(f"📁 {len(problems)}개 문제를 {output_file}로 내보냈습니다.")
        return output_file
    
    def _get_difficulty_stats(self, problems: List[CTFProblem]) -> Dict[str, int]:
        """난이도별 통계를 반환합니다."""
        stats = {'Easy': 0, 'Medium': 0, 'Hard': 0, 'Expert': 0}
        for problem in problems:
            stats[problem.difficulty] = stats.get(problem.difficulty, 0) + 1
        return stats
    
    def validate_generated_problems(self, problems: List[CTFProblem]) -> Dict[str, List[str]]:
        """생성된 문제들의 품질을 검증합니다."""
        issues = {
            'missing_files': [],
            'weak_flags': [],
            'difficulty_mismatch': [],
            'incomplete_solutions': []
        }
        
        for problem in problems:
            # 파일 존재 확인
            for file_path in problem.files:
                if not os.path.exists(file_path):
                    issues['missing_files'].append(f"{problem.id}: {file_path}")
            
            # 플래그 강도 확인
            if len(problem.flag) < 15 or not any(c.isdigit() for c in problem.flag):
                issues['weak_flags'].append(f"{problem.id}: {problem.flag}")
            
            # 난이도 일치성 확인
            classified_difficulty, _ = self.difficulty_classifier.classify_difficulty(problem)
            if classified_difficulty.value != problem.difficulty:
                issues['difficulty_mismatch'].append(
                    f"{problem.id}: {problem.difficulty} -> {classified_difficulty.value}"
                )
            
            # 해법 완성도 확인
            if len(problem.solution.strip()) < 20:
                issues['incomplete_solutions'].append(problem.id)
        
        return issues

if __name__ == "__main__":
    # 테스트 및 시연
    print("🎨 CTF 문제 생성기 v3.0 시연")
    print("=" * 60)
    
    generator = CTFProblemGenerator()
    
    # 35개 문제 생성
    problems = generator.generate_problem_set(35)
    
    # 생성 결과 통계
    stats = generator._get_difficulty_stats(problems)
    print(f"\n📊 생성된 문제 통계:")
    print(f"총 문제 수: {len(problems)}개")
    for difficulty, count in stats.items():
        percentage = count / len(problems) * 100 if problems else 0
        print(f"  - {difficulty}: {count}개 ({percentage:.1f}%)")
    
    # 기법별 분포
    technique_stats = {}
    for problem in problems:
        tech = problem.technique
        technique_stats[tech] = technique_stats.get(tech, 0) + 1
    
    print(f"\n🔧 기법별 분포:")
    for technique, count in sorted(technique_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {technique}: {count}개")
    
    # 문제 품질 검증
    print(f"\n🔍 문제 품질 검증...")
    validation_issues = generator.validate_generated_problems(problems)
    
    total_issues = sum(len(issue_list) for issue_list in validation_issues.values())
    print(f"발견된 이슈: {total_issues}개")
    
    for issue_type, issue_list in validation_issues.items():
        if issue_list:
            print(f"  - {issue_type}: {len(issue_list)}개")
            for issue in issue_list[:3]:  # 처음 3개만 표시
                print(f"    * {issue}")
            if len(issue_list) > 3:
                print(f"    * ... 그 외 {len(issue_list)-3}개 더")
    
    # 파일로 내보내기
    export_file = generator.export_problem_set(problems)
    
    print(f"\n🎉 {len(problems)}개 교육용 문제 생성 완료!")
    print(f"📁 내보내진 파일: {export_file}")
    print(f"🗂️ 문제 파일 위치: {generator.output_dir}")
    
    # 샘플 문제 몇 개 출력
    print(f"\n📝 샘플 문제 미리보기:")
    for i, problem in enumerate(problems[:3]):
        print(f"\n{i+1}. {problem.title}")
        print(f"   난이도: {problem.difficulty}")
        print(f"   기법: {problem.technique}")
        print(f"   플래그: {problem.flag}")
        print(f"   설명: {problem.description}")
        print(f"   해법: {problem.solution}")