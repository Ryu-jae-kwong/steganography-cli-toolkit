# Contributing to Steganography CLI Toolkit

Thank you for your interest in contributing to the Steganography CLI Toolkit! This document provides guidelines for contributing to the project.

## 🎯 Ways to Contribute

### 1. Bug Reports
- Use GitHub Issues to report bugs
- Include system information (OS, Python version)
- Provide steps to reproduce the issue
- Include error messages and stack traces

### 2. Feature Requests
- Describe the feature and its use case
- Explain how it would benefit users
- Consider implementation complexity

### 3. Code Contributions
- Fork the repository
- Create a feature branch
- Write clean, documented code
- Add tests for new functionality
- Ensure all tests pass

### 4. Documentation
- Improve existing documentation
- Add examples and tutorials
- Translate documentation to other languages

## 🛠️ Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/steganography-cli-toolkit.git
cd steganography-cli-toolkit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📝 Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings for classes and functions
- Keep functions focused and small

### Code Formatting
```bash
# Format code with black
black .

# Sort imports with isort
isort .

# Lint with flake8
flake8 .
```

## 🧪 Testing

- Write tests for new features
- Ensure all existing tests pass
- Aim for high test coverage
- Use pytest for testing framework

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=core --cov=v4_modules

# Run specific test file
python -m pytest tests/test_lsb.py
```

## 🚀 Pull Request Process

1. **Create Issue**: Discuss major changes in an issue first
2. **Fork & Branch**: Create a feature branch from main
3. **Implement**: Write code following our style guidelines
4. **Test**: Ensure all tests pass and add new tests
5. **Document**: Update documentation as needed
6. **Submit PR**: Provide clear description of changes

### PR Checklist
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] No breaking changes (or clearly marked)
- [ ] Commit messages are clear

## 🔍 Review Process

- Maintainers will review PRs within 3-5 business days
- Address feedback promptly
- Keep PRs focused and reasonably sized
- Be patient and respectful during review

## 🎓 Adding New Algorithms

To add a new steganography algorithm:

1. Create a new file in `core/` directory
2. Implement the base interface:
   ```python
   class NewAlgorithm:
       def embed_message(self, image_path, message, output_path, **kwargs):
           # Implementation here
           pass
       
       def extract_message(self, image_path, **kwargs):
           # Implementation here
           pass
   ```
3. Add tests in `tests/test_newalgorithm.py`
4. Update factory pattern in `core/factory.py`
5. Add documentation

## 🐛 Bug Report Template

```markdown
**Bug Description**
A clear description of the bug.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. See error

**Expected Behavior**
What you expected to happen.

**Environment**
- OS: [e.g. macOS 12.0]
- Python Version: [e.g. 3.9.0]
- Toolkit Version: [e.g. v4.0.0]

**Additional Context**
Any other context about the problem.
```

## 💡 Feature Request Template

```markdown
**Feature Description**
Clear description of the feature you'd like to see.

**Use Case**
Why would this feature be useful? Who would benefit?

**Possible Implementation**
If you have ideas about how to implement this feature.

**Additional Context**
Any other context or screenshots about the feature.
```

## 🔒 Security Guidelines

- Report security vulnerabilities privately
- Don't commit sensitive data (keys, passwords)
- Follow secure coding practices
- Use the toolkit responsibly and legally

## 📚 Documentation Standards

- Use clear, concise language
- Include code examples
- Update README.md for user-facing changes
- Add inline code comments for complex logic

## 🏆 Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

## ❓ Questions?

- Check existing issues and documentation
- Ask questions in GitHub Discussions
- Reach out to maintainers

Thank you for contributing to the Steganography CLI Toolkit! 🎉