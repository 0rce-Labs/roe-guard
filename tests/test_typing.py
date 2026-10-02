"""PEP 561 marker: the package ships inline types."""

from pathlib import Path

import roe_guard


def test_py_typed_marker_exists() -> None:
    assert Path(roe_guard.__file__).with_name("py.typed").is_file()
