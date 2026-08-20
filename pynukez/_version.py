"""Single source of truth for the pynukez package version.

The version lives in this dependency-free module so that both the package
root (``pynukez.__version__``) and the HTTP layer's User-Agent header can
derive from the same string without creating a circular import. Bump this
value together with the ``version`` field in ``pyproject.toml`` when
releasing.
"""

__version__ = "4.0.24"
