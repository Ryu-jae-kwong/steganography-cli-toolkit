# Steganography CLI Toolkit v5.0

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Algorithms](https://img.shields.io/badge/algorithms-10%2B-brightgreen)](#algorithms)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](README.md)

**Professional Digital Forensics & Steganography Analysis Tool**

A comprehensive command-line toolkit for steganography analysis, digital forensics, and CTF challenges. Features 10+ detection algorithms, multi-language support, and professional output formatting for security professionals and researchers.

## Key Features

### Advanced Algorithm Support
- **10+ Detection Algorithms**: LSB, DCT, DWT, F5, BPCS, Alpha Channel, JSteg, PVD, Histogram Shifting, and more
- **Professional Analysis**: Advanced metadata parsing, statistical anomaly detection
- **Archive Support**: ZIP, RAR, 7Z file analysis capabilities
- **Hash Verification**: MD5, SHA-1, SHA-256 integrity checking

### Professional Output System
- **5 Output Styles**: Minimal, Detailed, Compact, Structured, Progressive
- **Multi-Language**: English and Korean localization support
- **Clean Interface**: Professional formatting without emoji clutter
- **Configurable**: Persistent user preferences and settings

### Modern Architecture
- **Single Command**: Simple `python analyze.py image.png` usage
- **Modular Design**: Clean separation of algorithms and core systems
- **Cross-Platform**: Windows, macOS, Linux support
- **Performance Optimized**: Efficient analysis with comprehensive reporting

## Algorithms

The toolkit includes comprehensive steganography detection algorithms:

- **LSB (Least Significant Bit)**: Basic bit-plane analysis
- **DCT (Discrete Cosine Transform)**: JPEG coefficient analysis  
- **DWT (Discrete Wavelet Transform)**: Multi-level wavelet decomposition
- **F5**: JPEG matrix encoding detection
- **BPCS (Bit-Plane Complexity Segmentation)**: Complexity-based detection
- **Alpha Channel**: PNG transparency analysis
- **JSteg**: JPEG coefficient modification detection
- **PVD (Pixel Value Differencing)**: Pixel difference analysis
- **Histogram Shifting**: Histogram modification detection
- **Statistical Analysis**: Entropy and distribution analysis

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ryujaegwang/steganography-cli-toolkit.git
cd steganography-cli-toolkit

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Analyze single image (default: minimal style, English)
python analyze.py image.png

# Use different output styles
python analyze.py image.png --style detailed
python analyze.py image.png --style compact

# Multi-language support
python analyze.py image.png --lang korean

# Comprehensive analysis
python analyze.py image.png --comprehensive
```

## System Requirements

- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum, 8GB recommended
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

## Project Structure

```
steganography-cli-toolkit/
├── analyze.py                # Main analysis script
├── config/                   # Configuration management
│   ├── config.py            # Settings and preferences
│   └── localization.py      # Multi-language support
├── core/                     # Core analysis engine
│   └── comprehensive_analyzer.py  # Main analysis coordinator
├── algorithms/               # Algorithm implementations
│   ├── lsb_analyzer.py      # LSB detection
│   ├── dct_analyzer.py      # DCT analysis
│   ├── dwt_analyzer.py      # DWT analysis
│   ├── f5_analyzer.py       # F5 detection
│   ├── bpcs_analyzer.py     # BPCS analysis
│   ├── alpha_analyzer.py    # Alpha channel analysis
│   ├── jsteg_analyzer.py    # JSteg detection
│   ├── pvd_analyzer.py      # PVD analysis
│   └── histogram_analyzer.py # Histogram analysis
├── output/                   # Output formatting
│   └── output_formatter.py  # Multi-style formatting
├── examples/                 # Test images and samples
└── requirements.txt         # Python dependencies
```

## Output Styles

The toolkit supports 5 professional output styles:

### Minimal (Default)
- Clean, concise results
- Essential information only
- Perfect for quick analysis

### Detailed
- Comprehensive analysis reports
- Algorithm-specific findings
- Technical details and metrics

### Compact
- Space-efficient formatting
- Tabular data presentation
- Ideal for batch processing

### Structured
- JSON-compatible output
- Hierarchical data organization
- Machine-readable format

### Progressive
- Step-by-step analysis display
- Real-time progress indication
- Interactive analysis experience

## Configuration

The toolkit maintains user preferences in a configuration file:

```bash
# View current configuration
python analyze.py --show-config

# Set default output style
python analyze.py --set-style detailed

# Set default language
python analyze.py --set-lang korean

# Reset to defaults
python analyze.py --reset-config
```

## Version 5.0 Updates

### New Features
- **10+ Algorithms**: Expanded from 4 to 10+ detection algorithms
- **Professional Output**: 5 distinct formatting styles with clean, professional appearance
- **Multi-Language**: Full English and Korean localization support
- **Archive Analysis**: ZIP, RAR, 7Z file analysis capabilities
- **Hash Verification**: MD5, SHA-1, SHA-256 integrity checking
- **Configuration System**: Persistent user preferences and settings
- **Simplified CLI**: Single-command usage with intuitive options

### Architecture Improvements
- **Modular Design**: Clean separation of algorithms, core system, and output formatting
- **Professional Interface**: Removed emoji clutter for serious security work
- **Performance Optimization**: Streamlined analysis pipeline
- **Error Handling**: Robust exception handling and graceful degradation
- **Code Quality**: Comprehensive refactoring for maintainability

### Breaking Changes
- Command line interface changed from `v4_main.py` to `analyze.py`
- Output format standardized across all algorithms
- Configuration system replaces command-line flags for persistent settings

## Educational Use

Perfect for:
- **Digital Forensics Training**: Professional-grade analysis techniques
- **Security Research**: Advanced steganography detection methods
- **Academic Projects**: Well-documented, production-quality codebase
- **CTF Preparation**: Comprehensive algorithm coverage

## Contributing

Contributions welcome! Please ensure:
- Code follows existing style conventions
- New algorithms include comprehensive tests
- Documentation updated for new features
- Localization strings added for both languages

## Security & Ethics

This tool is designed for:
- Defensive security research
- Digital forensics investigation
- Educational purposes
- Authorized security testing

Please use responsibly and in accordance with applicable laws and regulations.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/ryujaegwang/steganography-cli-toolkit/issues)
- **Documentation**: See examples directory for usage samples

---

**Professional steganography analysis for security researchers**