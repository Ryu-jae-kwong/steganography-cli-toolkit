"""
네트워크 스테가노그래피 모듈 v3.0

이 패키지는 네트워크 프로토콜을 이용한 다양한 스테가노그래피 기법들을 제공합니다.
- TCP/IP 헤더 조작
- ICMP 코버트 채널
- DNS 터널링
- HTTP 헤더 조작
- 패킷 타이밍 조작
- 네트워크 흐름 분석

지원 프로토콜:
- TCP (Transmission Control Protocol)
- UDP (User Datagram Protocol) 
- ICMP (Internet Control Message Protocol)
- DNS (Domain Name System)
- HTTP/HTTPS (HyperText Transfer Protocol)
"""

from .tcp_steganography import TCPSteganography
from .icmp_covert import ICMPCovertChannel
from .dns_tunneling import DNSTunneling
from .http_steganography import HTTPSteganography
from .packet_timing import PacketTimingSteganography

__all__ = [
    'TCPSteganography',
    'ICMPCovertChannel',
    'DNSTunneling', 
    'HTTPSteganography',
    'PacketTimingSteganography'
]

__version__ = "3.0.0"
__author__ = "디지털포렌식 연구소"