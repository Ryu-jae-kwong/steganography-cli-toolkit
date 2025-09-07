# 🔐 Steganography CLI Toolkit v4.0

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CTF Success Rate](https://img.shields.io/badge/CTF%20Success%20Rate-100%25-brightgreen)](docs/v4.0_완전사용자가이드.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](README.md)

**Professional Digital Forensics & Steganography Analysis Tool**

A comprehensive command-line toolkit for steganography analysis, digital forensics, and CTF challenges. Achieved **100% CTF success rate** with advanced metadata analysis, statistical detection, and ZIP-to-Image conversion capabilities.

## ✨ Key Features

### 🎯 **Real-World Validated**
- **100% CTF Success Rate**: Solved 3/3 real CTF challenges
- **Production-Ready**: Used in actual digital forensics investigations
- **Expert-Level Analysis**: Advanced metadata parsing and statistical anomaly detection

### 🔍 **Advanced Analysis Capabilities**
- **Metadata Extraction**: PNG zTXt chunks, EXIF data, compressed metadata
- **Statistical Analysis**: Multi-file comparison, anomaly detection, pattern recognition
- **ZIP-Image Conversion**: Analyze files converted from ZIP to image formats
- **Multi-Algorithm Support**: LSB, DCT, DWT, F5 steganography techniques
- **Performance Monitoring**: Real-time benchmarking and optimization

### 🚀 **Modern Architecture**
- **4-Module Design**: Simplified from 42-file v3.0 to focused core modules
- **Rich CLI Interface**: Beautiful terminal UI with progress bars and tables
- **Parallel Processing**: Multi-threaded analysis for enhanced performance
- **Cross-Platform**: Windows, macOS, Linux support

## 🏆 CTF Success Stories

### ✅ Solved Challenges

| Challenge | Technique Used | Key Discovery |
|-----------|----------------|---------------|
| **Hit a Brick Wall** | PNG zTXt chunk analysis | Hex-encoded EXIF metadata in compressed chunks |
| **Turtles All The Way Down** | Statistical anomaly detection | Password discovery in 20.png EXIF data |
| **Hidden** | ZIP-to-Image conversion | Reconstructed winsock32.dll from pixel data |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ryujaegwang/steganography-cli-toolkit.git
cd steganography-cli-toolkit

# Install dependencies
pip install -r requirements.txt

# Run quick test
python v4_main.py --quick-test
```

### Basic Usage

```bash
# Quick system test
python v4_main.py --quick-test

# Analyze single image
python v4_main.py --analyze image.png

# Performance benchmark
python v4_main.py --benchmark

# Help and options
python v4_main.py --help
```

## 📋 System Requirements

- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 2GB free space for analysis cache
- **Platform**: Windows 10+, macOS 10.15+, Linux (Ubuntu 18.04+)

### Dependencies

```
rich>=13.0.0          # Beautiful CLI interface
psutil>=5.8.0         # System monitoring
Pillow>=9.0.0         # Image processing
numpy>=1.20.0         # Numerical analysis
cryptography>=3.4.0   # Encryption support
```

## 📁 Project Structure

```
steganography-cli-toolkit/
├── v4_main.py                 # Main CLI entry point
├── v4_modules/               # Core v4.0 modules
│   ├── cli_interface.py      # Rich-based CLI
│   ├── batch_processor.py    # Parallel processing
│   ├── performance_monitor.py # Benchmarking
│   └── ctf_simulator.py      # CTF challenge simulation
├── core/                     # Algorithm implementations
│   ├── lsb.py               # LSB steganography
│   ├── dct.py               # DCT algorithm
│   ├── dwt.py               # DWT algorithm
│   ├── f5.py                # F5 algorithm
│   ├── statistical.py       # Statistical analysis
│   └── metadata.py          # Metadata extraction
├── examples/                 # Sample files and CTF challenges
├── docs/                    # Complete documentation
│   └── v4.0_완전사용자가이드.md
├── tests/                   # Test suites
└── requirements.txt         # Python dependencies
```

## 🔧 Advanced Features

### Metadata Analysis
```bash
# Extract and analyze PNG metadata
python v4_main.py --analyze --metadata-deep image.png

# Search for hidden text in compressed chunks
python v4_main.py --analyze --chunk-analysis image.png
```

### Statistical Detection
```bash
# Multi-file anomaly detection
python v4_main.py --analyze --statistical folder/*.png

# Color distribution analysis
python v4_main.py --analyze --color-stats image.png
```

### ZIP-Image Analysis
```bash
# Analyze ZIP-to-Image converted files
python v4_main.py --analyze --zip-conversion suspicious.png

# Reconstruct original ZIP from image
python v4_main.py --extract --reconstruct-zip image.png output.zip
```

## 📊 Performance Benchmarks

| Operation | v3.0 Time | v4.0 Time | Improvement |
|-----------|-----------|-----------|-------------|
| Single Image Analysis | 15.2s | 3.8s | **4x faster** |
| Multi-File Processing | 45.7s | 12.1s | **3.8x faster** |
| Metadata Extraction | 8.3s | 1.2s | **6.9x faster** |
| Statistical Analysis | 22.1s | 5.7s | **3.9x faster** |

*Benchmarked on macOS with 16GB RAM, M1 Pro processor*

## 🎓 Educational Use

Perfect for:
- **Digital Forensics Courses**: Real-world analysis techniques
- **CTF Training**: Practice with solved challenge examples
- **Security Research**: Advanced steganography detection methods
- **Academic Projects**: Well-documented, production-quality code

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/ryujaegwang/steganography-cli-toolkit.git
cd steganography-cli-toolkit

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
python -m flake8 .
```

## 📚 Documentation

- **[Complete User Guide](docs/v4.0_완전사용자가이드.md)**: 57-page comprehensive manual
- **[API Documentation](docs/api-reference.md)**: Technical API reference
- **[CTF Walkthroughs](examples/ctf-challenges/)**: Detailed challenge solutions
- **[Algorithm Details](docs/algorithms.md)**: Technical implementation details

## 🏅 Version History

| Version | Key Features | CTF Success Rate |
|---------|--------------|------------------|
| v4.0.0 | Metadata analysis, Statistical detection, ZIP-Image conversion | **100% (3/3)** |
| v3.0.0 | 42-file modular architecture, Audio support | 0% (0/3) |
| v2.0.0 | CLI interface, Batch processing | 0% (0/3) |
| v1.0.0 | Core algorithms (LSB, DCT, DWT, F5) | 0% (0/3) |

## 🔒 Security & Ethics

This tool is designed for:
- ✅ **Defensive security research**
- ✅ **Digital forensics investigation**
- ✅ **Educational purposes**
- ✅ **CTF challenges and training**

Please use responsibly and in accordance with applicable laws and regulations.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by real CTF challenges from various competitions
- Built with feedback from digital forensics professionals
- Thanks to the steganography research community

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/ryujaegwang/steganography-cli-toolkit/issues)
- **Documentation**: [Complete Guide](docs/v4.0_완전사용자가이드.md)
- **Examples**: [CTF Solutions](examples/ctf-challenges/)

---

⭐ **Star this project** if it helps with your digital forensics work!

**Made with ❤️ for the cybersecurity community**