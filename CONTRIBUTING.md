# Contributing to Steganography CLI Toolkit v5.0

Professional steganography analysis toolkit contribution guidelines.

## Ways to Contribute

### Bug Reports
- Use GitHub Issues for bug reports
- Include system information (OS, Python version)
- Provide reproduction steps with error messages

### Feature Requests  
- Describe the feature and its use case
- Explain benefits for security professionals
- Consider implementation complexity

### Code Contributions
- Fork the repository and create feature branch
- Follow existing code style and patterns
- Ensure all functionality works before submission

## Development Setup

```bash
git clone https://github.com/ryujaegwang/steganography-cli-toolkit.git
cd steganography-cli-toolkit
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Testing Your Changes

```bash
# Test basic functionality
python analyze.py test_image.png

# Test different output styles
python analyze.py test_image.png --style detailed
python analyze.py test_image.png --style compact

# Verify algorithm imports
python -c "from core.comprehensive_analyzer import ComprehensiveAnalyzer; print('Core OK')"
```

## Code Standards

- Follow PEP 8 style guidelines
- Use descriptive variable and function names
- Add docstrings for classes and functions
- Keep functions focused and small

## Adding New Algorithms

1. Create new file in `algorithms/` directory following pattern:
```python
class NewAlgorithmAnalyzer:
    def analyze(self, image_path, **kwargs):
        # Implementation here
        return {
            'status': 'positive' or 'negative', 
            'confidence': float,  # 0.0 to 1.0
            'details': {}
        }
```

2. Register in `core/comprehensive_analyzer.py`
3. Test with: `python analyze.py test_image.png`

## Pull Request Process

1. Create issue to discuss major changes first
2. Fork and create feature branch from main
3. Implement changes following style guidelines  
4. Test thoroughly with various image formats
5. Submit PR with clear description of changes

### PR Requirements
- Tests pass with sample images
- Code follows existing patterns
- No breaking changes to CLI interface
- Clear commit messages

## Project Structure

```
steganography-cli-toolkit/
├── analyze.py              # Main CLI entry point
├── algorithms/             # Detection algorithms (10+ implementations)
├── core/                   # Core analysis engine
├── requirements.txt        # Dependencies
├── README.md              # Documentation
├── CONTRIBUTING.md        # This file
└── LICENSE                # MIT License
```

## Bug Report Template

**Bug Description**
Clear description of the issue.

**Reproduction Steps**
1. Command executed
2. Image file used
3. Expected vs actual behavior

**Environment**
- OS: [e.g. macOS 13.0]
- Python Version: [e.g. 3.9.0] 
- Toolkit Version: v5.0

## Feature Request Template

**Feature Description**
Clear description of proposed functionality.

**Use Case** 
Why would this benefit security professionals?

**Implementation Ideas**
Suggestions for technical approach if any.

## Security Guidelines

- Report security issues privately via GitHub
- Do not commit sensitive data or credentials
- Follow secure coding practices
- Use toolkit for authorized security testing only

## Recognition

Contributors recognized in:
- README.md contributors section
- GitHub contributors page
- Release notes for significant contributions

## Questions

- Check existing documentation and issues first
- Use GitHub Issues for questions
- Provide context and relevant details

Professional digital forensics toolkit - contribute responsibly.