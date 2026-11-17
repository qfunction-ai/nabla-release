"""Tests for the structured logging module."""

import logging
import os
import tempfile

from nabla.log import get_logger, _ensure_initialized


def test_get_logger_returns_namespaced_logger():
    """get_logger should return a logger under the nabla namespace."""
    logger = get_logger("test_module")
    assert logger.name == "nabla.test_module"


def test_get_logger_returns_python_logger():
    """get_logger should return a standard Python logging.Logger."""
    logger = get_logger("pipeline")
    assert isinstance(logger, logging.Logger)


def test_root_logger_has_console_handler():
    """The nabla root logger should have a console handler."""
    _ensure_initialized()
    root = logging.getLogger("nabla")
    handler_types = [type(h).__name__ for h in root.handlers]
    assert "StreamHandler" in handler_types


def test_root_logger_level():
    """The nabla root logger should be set to DEBUG."""
    _ensure_initialized()
    root = logging.getLogger("nabla")
    assert root.level == logging.DEBUG


def test_console_handler_level():
    """The console handler should filter at INFO level."""
    _ensure_initialized()
    root = logging.getLogger("nabla")
    for h in root.handlers:
        if type(h).__name__ == "StreamHandler":
            assert h.level == logging.INFO
            return
    assert False, "No StreamHandler found"


def test_file_handler_created_when_data_dir_exists():
    """File handler should be created when data dir is writable."""
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["NABLA_DATA_DIR"] = tmp
        # Reset initialization state and settings cache
        import nabla.log
        import nabla.config
        nabla.log._initialized = False
        nabla.config._settings = None
        # Clear existing handlers
        root = logging.getLogger("nabla")
        root.handlers.clear()

        try:
            _ensure_initialized()
            handler_types = [type(h).__name__ for h in root.handlers]
            assert "RotatingFileHandler" in handler_types
        finally:
            del os.environ["NABLA_DATA_DIR"]
            nabla.log._initialized = False
            nabla.config._settings = None
            root.handlers.clear()


def test_file_handler_skipped_when_data_dir_missing():
    """File handler should be skipped gracefully when data dir isn't writable."""
    os.environ["NABLA_DATA_DIR"] = "/nonexistent/path/that/cant/be/created"
    import nabla.log
    import nabla.config
    nabla.log._initialized = False
    nabla.config._settings = None
    root = logging.getLogger("nabla")
    root.handlers.clear()

    try:
        _ensure_initialized()
        handler_types = [type(h).__name__ for h in root.handlers]
        # Should only have console handler, no file handler
        assert "RotatingFileHandler" not in handler_types
        assert "StreamHandler" in handler_types
    finally:
        del os.environ["NABLA_DATA_DIR"]
        nabla.log._initialized = False
        nabla.config._settings = None
        root.handlers.clear()
