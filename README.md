# Steganography CLI Toolkit v5.0

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Algorithms](https://img.shields.io/badge/algorithms-10%2B-brightgreen)](#algorithms)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](README.md)

**Professional Digital Forensics and Steganography Analysis Tool**

Comprehensive command-line toolkit for steganography detection and digital forensics. Features 10+ detection algorithms with professional output formatting for security professionals and researchers.

## Core Features

**Algorithm Suite**: 10+ steganography detection algorithms including LSB, DCT, DWT, F5, BPCS, Alpha Channel, JSteg, PVD, Histogram, and Statistical analysis.

**Professional Output**: Five distinct output styles (Minimal, Detailed, Compact, Structured, Progressive) with clean, professional formatting.

**Multi-Language**: English and Korean localization support.

**Hash Verification**: MD5, SHA-1, SHA-256 integrity checking.

**Archive Analysis**: ZIP, RAR, 7Z file examination capabilities.

**Single Command Interface**: Simple `python analyze.py image.png` usage.

## Installation

```bash
git clone https://github.com/ryujaegwang/steganography-cli-toolkit.git
cd steganography-cli-toolkit
pip install -r requirements.txt
```

## Usage

```bash
# Basic analysis
python analyze.py image.png

# Detailed output
python analyze.py image.png --style detailed

# Compact format
python analyze.py image.png --style compact

# Korean language
python analyze.py image.png --lang korean
```

## Detection Algorithms

- **LSB (Least Significant Bit)**: Bit-plane analysis
- **DCT (Discrete Cosine Transform)**: JPEG coefficient analysis  
- **DWT (Discrete Wavelet Transform)**: Wavelet decomposition analysis
- **F5**: JPEG matrix encoding detection
- **BPCS (Bit-Plane Complexity Segmentation)**: Complexity-based detection
- **Alpha Channel**: PNG transparency analysis
- **JSteg**: JPEG coefficient modification detection
- **PVD (Pixel Value Differencing)**: Pixel difference analysis
- **Histogram**: Histogram modification detection
- **Statistical**: Entropy and distribution analysis

## System Requirements

- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum
- **Platform**: Windows 10+, macOS 10.15+, Linux (Ubuntu 18.04+)

### Dependencies

```
Pillow>=9.0.0         # Image processing
numpy>=1.20.0         # Numerical analysis
scipy>=1.7.0          # Scientific computing
scikit-image>=0.18.0  # Image analysis
PyWavelets>=1.3.0     # Wavelet transforms
rarfile>=4.0          # RAR archive support
py7zr>=0.20.0         # 7Z archive support
```

## Output Styles

**Minimal**: Essential results only, ideal for quick analysis.

**Detailed**: Comprehensive analysis with technical details and algorithm-specific findings.

**Compact**: Space-efficient tabular format, suitable for batch processing.

**Structured**: JSON-compatible hierarchical output, machine-readable format.

**Progressive**: Step-by-step analysis with real-time progress indication.

## Project Structure

```
steganography-cli-toolkit/
├── algorithms/                   # Detection algorithm implementations
├── analyze.py                    # Main analysis script
│   ├── lsb_analyzer.py          # LSB detection
│   ├── dct_analyzer.py          # DCT analysis
│   ├── dwt_analyzer.py          # DWT analysis
│   ├── f5_analyzer.py           # F5 detection
│   ├── bpcs_analyzer.py         # BPCS analysis
│   ├── alpha_analyzer.py        # Alpha channel analysis
│   ├── jsteg_analyzer.py        # JSteg detection
│   ├── pvd_analyzer.py          # PVD analysis
│   ├── histogram_analyzer.py    # Histogram analysis
│   └── statistical_analyzer.py # Statistical analysis
├── core/                        # Core analysis engine
│   ├── comprehensive_analyzer.py # Main analysis coordinator
│   ├── exceptions.py            # Exception handling
│   ├── localization.py          # Multi-language support
│   └── metadata.py              # Metadata analysis
├── requirements.txt             # Python dependencies
├── CONTRIBUTING.md              # Contribution guidelines
└── LICENSE                      # MIT License
```

## Architecture

**Modular Design**: Clean separation between algorithms, core engine, and output formatting.

**Single Entry Point**: All functionality accessible through `analyze.py`.

**Algorithm Independence**: Each detection algorithm operates independently with standardized output format.

**Extensible**: New algorithms can be added by implementing the standard analyzer interface.

## Educational Use

Suitable for:
- Digital forensics training
- Security research and development
- Academic cybersecurity projects
- CTF preparation and practice

## Professional Applications

Designed for:
- Digital forensics investigations
- Security analysis workflows
- Authorized penetration testing
- Research and development

## Version 5.0 Updates

**Architecture Refactor**: Complete redesign from v4.0 with simplified, professional interface.

**Algorithm Expansion**: Increased from 4 to 10+ detection algorithms.

**Output System**: Five professional output styles replacing emoji-based formatting.

**Multi-Language**: Full English and Korean localization support.

**Performance**: Optimized analysis pipeline with efficient resource usage.

**Professional Interface**: Clean CLI design suitable for enterprise environments.

## Contributing

Contributions welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, testing requirements, and submission process.

## Security and Ethics

This tool is designed for defensive security research, digital forensics investigation, and educational purposes. Use responsibly and in accordance with applicable laws and regulations.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/ryujaegwang/steganography-cli-toolkit/issues)
- **Documentation**: See CONTRIBUTING.md for development guidelines

Professional steganography analysis for security professionals.
