# ACE Projects Development Environment Guide

This guide documents the standard development environment, tools, and practices used across ACE IoT Solutions Python projects. It serves as a reference for both human developers and AI assistants working on ACE projects.

## Table of Contents

1. [Core Tools](#core-tools)
2. [Project Structure](#project-structure)
3. [Development Workflow](#development-workflow)
4. [Testing Standards](#testing-standards)
5. [Type Safety](#type-safety)
6. [Code Quality](#code-quality)
7. [CI/CD Configuration](#cicd-configuration)
8. [Release Process](#release-process)
9. [AI Assistant Guidelines](#ai-assistant-guidelines)

## Core Tools

### Package Management: UV

We use `uv` as our primary package and project management tool.

```bash
# Installation
curl -LsSf https://astral.sh/uv/install.sh | sh

# Common commands
uv sync                    # Install dependencies
uv sync --all-extras      # Install with all extras (dev, test, etc.)
uv run pytest             # Run commands in venv
uv add package_name       # Add a dependency
uv add --dev package_name # Add a dev dependency
```

**Key Features:**
- Fast dependency resolution
- Automatic virtual environment management
- Lock file support (uv.lock)
- Compatible with pyproject.toml

### Linting and Formatting: Ruff

Ruff is our all-in-one Python linter and formatter.

```toml
# pyproject.toml configuration
[tool.ruff]
line-length = 100
target-version = "py310"
extend-exclude = ["migrations", "__pycache__", ".venv"]

[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # pyflakes
    "I",    # isort
    "UP",   # pyupgrade
    "B",    # flake8-bugbear
    "C4",   # flake8-comprehensions
    "DTZ",  # flake8-datetimez
    "T20",  # flake8-print
    "SIM",  # flake8-simplify
    "RET",  # flake8-return
]
ignore = ["E203", "B008", "B905", "E731"]
fixable = ["ALL"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "PLR2004", "ARG001", "ARG002"]
"**/__init__.py" = ["F401", "D104"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
```

**Usage:**
```bash
uv run ruff check .          # Lint code
uv run ruff format .         # Format code
uv run ruff check --fix .    # Auto-fix linting issues
```

### Type Checking: Pyrefly

Pyrefly is our type checker of choice for its speed and Pydantic support.

```toml
# pyproject.toml configuration
[tool.pyrefly]
project_includes = ["src", "tests"]
project_excludes = [".venv", "build", "dist"]
python_version = "3.10"
```

**Usage:**
```bash
uv run pyrefly check src              # Type check source code
uv run pyrefly check src tests        # Include tests
uv run pyrefly dump-config src        # Show configuration
```

**Common Patterns:**
```python
# Pydantic Field with constraints (requires ignore)
field: int = Field(default=1, ge=0)  # pyrefly: ignore[no-matching-overload]

# Dynamic model creation
Model = create_model("Model", **fields)  # pyrefly: ignore[no-matching-overload]

# Mixin attribute access
self.unknown_attr  # pyrefly: ignore[missing-attribute]
```

### Testing: Pytest

Pytest is our testing framework with coverage support.

```toml
# pyproject.toml configuration
[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "-ra",
    "--strict-markers",
    "--cov=src",
    "--cov-branch",
    "--cov-report=term-missing:skip-covered",
    "--cov-report=xml",
    "--cov-report=html",
    "--cov-fail-under=80",
]
```

**Usage:**
```bash
uv run pytest                        # Run all tests
uv run pytest -v                     # Verbose output
uv run pytest tests/test_module.py   # Run specific test
uv run pytest -k "test_function"     # Run tests matching pattern
uv run pytest --cov                  # With coverage
```

### Pre-commit Hooks

Ensure code quality before commits:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: check-toml
      - id: debug-statements
      - id: mixed-line-ending

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.12.5
    hooks:
      - id: ruff
        args: ["--fix", "--exit-non-zero-on-fix"]
      - id: ruff-format
```

**Setup:**
```bash
uv add --dev pre-commit
uv run pre-commit install
uv run pre-commit run --all-files  # Run on all files
```

## Project Structure

Standard Python package structure:

```
project-name/
├── src/
│   └── package_name/
│       ├── __init__.py
│       ├── module.py
│       └── subpackage/
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   └── test_module.py
├── docs/
├── scripts/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── pyproject.toml
├── uv.lock
├── README.md
├── LICENSE
├── .gitignore
├── .pre-commit-config.yaml
└── ace-projects-env-guide.md
```

## Development Workflow

### 1. Initial Setup

```bash
# Clone repository
git clone git@github.com:ACE-IoT-Solutions/project-name.git
cd project-name

# Install dependencies
uv sync --all-extras

# Install pre-commit hooks
uv run pre-commit install

# Verify setup
uv run pytest
uv run ruff check .
uv run pyrefly check src
```

### 2. Development Cycle

```bash
# Create feature branch
git checkout -b feature/description

# Make changes
# ...

# Format and lint
uv run ruff format .
uv run ruff check --fix .

# Type check
uv run pyrefly check src

# Test
uv run pytest

# Commit (pre-commit hooks run automatically)
git add .
git commit -m "feat: add new feature"
```

### 3. Dependency Management

```bash
# Add runtime dependency
uv add pydantic

# Add dev dependency
uv add --dev pytest-mock

# Update dependencies
uv sync

# Lock dependencies
# (uv.lock is automatically updated)
```

## Testing Standards

### Test Organization

```python
# tests/test_module.py
import pytest
from package_name.module import MyClass


class TestMyClass:
    """Test MyClass functionality."""
    
    def test_initialization(self):
        """Test class initialization."""
        obj = MyClass(name="test")
        assert obj.name == "test"
    
    def test_method_with_mock(self, mocker):
        """Test method using mock."""
        mock_dep = mocker.patch("package_name.module.dependency")
        mock_dep.return_value = "mocked"
        
        obj = MyClass()
        result = obj.method()
        
        assert result == "mocked"
        mock_dep.assert_called_once()
    
    @pytest.mark.parametrize("input,expected", [
        ("test", "TEST"),
        ("hello", "HELLO"),
    ])
    def test_parametrized(self, input, expected):
        """Test with multiple inputs."""
        obj = MyClass()
        assert obj.upper(input) == expected
```

### Coverage Requirements

- Minimum coverage: 80%
- Focus on branch coverage
- Exclude test files from coverage
- Generate HTML reports for review

## Type Safety

### Pydantic Models

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class MyModel(BaseModel):
    """Example model with validation."""
    
    name: str = Field(..., min_length=1, max_length=100)
    age: int = Field(default=0, ge=0)  # pyrefly: ignore[no-matching-overload]
    email: Optional[str] = None
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure name is capitalized."""
        return v.capitalize()
```

### Type Hints Best Practices

```python
from typing import Any, Dict, List, Optional, Union, TypeVar, Generic

T = TypeVar("T")


class Repository(Generic[T]):
    """Generic repository pattern."""
    
    def __init__(self) -> None:
        self._items: Dict[str, T] = {}
    
    def add(self, key: str, item: T) -> None:
        """Add item to repository."""
        self._items[key] = item
    
    def get(self, key: str) -> Optional[T]:
        """Get item by key."""
        return self._items.get(key)
    
    def list(self) -> List[T]:
        """List all items."""
        return list(self._items.values())
```

## Code Quality

### Documentation Standards

```python
"""Module docstring explaining purpose and usage.

This module provides functionality for X, Y, and Z.
It's designed to be used in conjunction with module A.

Example:
    >>> from package import module
    >>> result = module.function(param)
    >>> print(result)
"""

from typing import Optional


def function(param: str, optional: Optional[int] = None) -> str:
    """Brief description of function.
    
    Longer description explaining the function's behavior,
    edge cases, and any important notes.
    
    Args:
        param: Description of param
        optional: Description of optional param (default: None)
    
    Returns:
        Description of return value
    
    Raises:
        ValueError: When param is invalid
        TypeError: When types don't match
    
    Example:
        >>> function("test", optional=42)
        'test-42'
    """
    if not param:
        raise ValueError("param cannot be empty")
    
    result = param
    if optional is not None:
        result = f"{param}-{optional}"
    
    return result
```

### Error Handling

```python
from typing import Union, Optional
import logging

logger = logging.getLogger(__name__)


class ProjectError(Exception):
    """Base exception for project."""
    pass


class ValidationError(ProjectError):
    """Validation error with details."""
    
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


def safe_operation(value: str) -> Union[str, None]:
    """Perform operation with proper error handling."""
    try:
        # Attempt operation
        result = risky_operation(value)
        return result
    except ValueError as e:
        logger.warning(f"Invalid value: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise ProjectError(f"Operation failed: {e}") from e
```

## CI/CD Configuration

### GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install uv
      uses: astral-sh/setup-uv@v3
    
    - name: Install dependencies
      run: |
        uv sync --all-extras
    
    - name: Run linting
      run: |
        uv run ruff check .
        uv run ruff format --check .
    
    - name: Run type checking
      run: |
        uv run pyrefly check src
    
    - name: Run tests
      run: |
        uv run pytest --cov --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v4
      with:
        token: ${{ secrets.CODECOV_TOKEN }}
```

### Type Checking with Baseline

For gradual type safety adoption:

```yaml
- name: Run type checking
  run: |
    # Run pyrefly with baseline approach
    ERROR_COUNT=$(uv run pyrefly check src 2>&1 | grep -oE 'errors shown: [0-9]+' | grep -oE '[0-9]+' || echo "0")
    echo "Type errors found: $ERROR_COUNT"
    
    # Set your baseline here
    BASELINE=10
    if [ "$ERROR_COUNT" -gt "$BASELINE" ]; then
      echo "Type check failed: $ERROR_COUNT errors found (baseline: $BASELINE)"
      exit 1
    fi
```

## Release Process

### Version Management

We follow semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

### Release Workflow

1. **Update Version**
   ```bash
   # Update version in pyproject.toml
   version = "0.3.4"
   
   # Update version in __init__.py
   __version__ = "0.3.4"
   ```

2. **Create Release Commit**
   ```bash
   git add pyproject.toml src/package/__init__.py
   git commit -m "Release v0.3.4"
   ```

3. **Tag Release**
   ```bash
   git tag -a v0.3.4 -m "Release v0.3.4"
   git push origin main
   git push origin v0.3.4
   ```

4. **Create GitHub Release**
   ```bash
   gh release create v0.3.4 \
     --title "Release v0.3.4" \
     --notes "Release notes here"
   ```

### Automated Publishing

```yaml
# .github/workflows/release.yml
name: Release

on:
  release:
    types: [published]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.10'
    
    - name: Install dependencies
      run: |
        pip install build twine
    
    - name: Build package
      run: python -m build
    
    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: |
        twine upload dist/*
```

## AI Assistant Guidelines

### Working with the Codebase

1. **Always read before writing**
   ```python
   # Bad: Write without context
   # Good: Read existing file first, understand patterns
   ```

2. **Use existing patterns**
   - Check imports in neighboring files
   - Follow existing code style
   - Use project's utility functions

3. **Type safety awareness**
   - Add pyrefly ignore comments when needed
   - Understand common type checking limitations
   - Maintain type annotations

4. **Testing approach**
   - Write tests for new functionality
   - Follow existing test patterns
   - Aim for high coverage

### Common Tasks

1. **Adding a new module**
   - Create file in appropriate package
   - Add to __init__.py exports
   - Create corresponding test file
   - Update documentation

2. **Fixing type errors**
   - Run pyrefly to identify issues
   - Add strategic ignore comments
   - Fix actual type mismatches
   - Update CI baseline if needed

3. **Refactoring code**
   - Ensure tests pass before starting
   - Make incremental changes
   - Run tests after each change
   - Update type hints as needed

### Best Practices

1. **Commit messages**
   ```
   feat: add new feature
   fix: resolve bug in module
   docs: update API documentation
   test: add tests for new feature
   refactor: simplify complex logic
   chore: update dependencies
   ```

2. **File handling**
   - Always use absolute paths
   - Read files before editing
   - Create parent directories if needed
   - Handle binary files appropriately

3. **Error handling**
   - Provide helpful error messages
   - Log errors appropriately
   - Handle edge cases
   - Test error paths

## Environment Variables

Common environment variables for ACE projects:

```bash
# Development
export ACE_ENV=development
export ACE_DEBUG=true
export ACE_LOG_LEVEL=DEBUG

# Testing
export ACE_TEST_DB=sqlite:///:memory:
export ACE_COVERAGE_MIN=80

# Production
export ACE_ENV=production
export ACE_API_KEY=secret-key
export ACE_DATABASE_URL=postgresql://...
```

## Troubleshooting

### Common Issues

1. **Import errors**
   - Ensure package is installed: `uv sync`
   - Check PYTHONPATH
   - Verify __init__.py files exist

2. **Type checking errors**
   - Update pyrefly: `uv add --dev pyrefly@latest`
   - Check for known patterns in this guide
   - Use appropriate ignore comments

3. **Test failures**
   - Run tests in isolation
   - Check for test interdependencies
   - Verify mock setup

4. **Pre-commit failures**
   - Run `uv run pre-commit run --all-files`
   - Fix issues incrementally
   - Update hooks if needed

## Additional Resources

- [UV Documentation](https://github.com/astral-sh/uv)
- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [Pyrefly Documentation](https://pyrefly.com/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Pydantic Documentation](https://docs.pydantic.dev/)

---

This guide is a living document. Update it as tools and practices evolve.