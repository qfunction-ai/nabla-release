"""Tests for Nabla configuration."""

import os


def test_settings_defaults():
    """Settings should have sensible defaults."""
    # Clear env overrides so we test the actual defaults
    env_backup = {}
    for key in list(os.environ):
        if key.startswith("NABLA_"):
            env_backup[key] = os.environ.pop(key)
    try:
        from nabla.config import Settings
        s = Settings()
        assert s.letta_base_url == "http://localhost:8284"
        assert s.llm_model == "ollama/gemma4:latest"
        assert s.embedding_model == "embeddinggemma:latest"
    finally:
        os.environ.update(env_backup)


def test_settings_env_override():
    """Settings should respect NABLA_* environment variables."""
    os.environ["NABLA_LETTA_BASE_URL"] = "http://custom:9999"
    try:
        from nabla.config import Settings
        s = Settings()
        assert s.letta_base_url == "http://custom:9999"
    finally:
        del os.environ["NABLA_LETTA_BASE_URL"]


def test_effective_tool_url():
    """effective_tool_url should fall back to letta_base_url when not set."""
    from nabla.config import Settings
    s = Settings()
    assert s.effective_tool_url == s.letta_base_url


def test_effective_tool_url_override():
    """effective_tool_url should use tool_letta_url when set."""
    from nabla.config import Settings
    s = Settings(tool_letta_url="http://letta:8283")
    assert s.effective_tool_url == "http://letta:8283"


def test_env_prefix():
    """All env vars should use NABLA_ prefix."""
    from nabla.config import Settings
    assert Settings.model_config.get("env_prefix") == "NABLA_"


# --- Property tests ---


def _clear_nabla_env():
    """Remove all NABLA_* env vars to avoid interference."""
    for key in list(os.environ):
        if key.startswith("NABLA_"):
            del os.environ[key]


def test_runs_file_property():
    """runs_file property returns data_dir + /runs.json."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(data_dir="/tmp/test_data")
    assert s.runs_file == "/tmp/test_data/runs.json"


def test_rl_state_file_property():
    """rl_state_file property returns data_dir + /rl_state.json."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(data_dir="/tmp/test_data")
    assert s.rl_state_file == "/tmp/test_data/rl_state.json"


def test_gcn_lof_model_file_property():
    """gcn_lof_model_file property returns data_dir + /gcn_lof_model.json."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(data_dir="/tmp/test_data")
    assert s.gcn_lof_model_file == "/tmp/test_data/gcn_lof_model.json"


def test_effective_watchlist_path_default():
    """effective_watchlist_path defaults to data_dir/watchlists.json when watchlist_path is empty."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(data_dir="/tmp/test_data", watchlist_path="")
    assert s.effective_watchlist_path == "/tmp/test_data/watchlists.json"


def test_effective_watchlist_path_override():
    """effective_watchlist_path uses watchlist_path when set."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(watchlist_path="/custom/watchlists.json")
    assert s.effective_watchlist_path == "/custom/watchlists.json"


def test_effective_ingestion_state_path_default():
    """effective_ingestion_state_path defaults to data_dir/ingestion_state.json when ingestion_state_path is empty."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(data_dir="/tmp/test_data", ingestion_state_path="")
    assert s.effective_ingestion_state_path == "/tmp/test_data/ingestion_state.json"


def test_effective_ingestion_state_path_override():
    """effective_ingestion_state_path uses ingestion_state_path when set."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings(ingestion_state_path="/custom/ingestion_state.json")
    assert s.effective_ingestion_state_path == "/custom/ingestion_state.json"


def test_splunk_query_map_keys():
    """splunk_query_map returns dict with auth/network/dns/endpoint keys."""
    _clear_nabla_env()
    from nabla.config import Settings
    s = Settings()
    qm = s.splunk_query_map
    assert set(qm.keys()) == {"auth", "network", "dns", "endpoint"}


def test_get_settings_caching():
    """get_settings returns same instance on repeated calls (caching)."""
    _clear_nabla_env()
    import importlib
    import nabla.config
    importlib.reload(nabla.config)
    s1 = nabla.config.get_settings()
    s2 = nabla.config.get_settings()
    assert s1 is s2


def test_get_settings_reset_creates_new():
    """After resetting _settings to None, get_settings returns a new instance."""
    _clear_nabla_env()
    import importlib
    import nabla.config
    importlib.reload(nabla.config)
    s1 = nabla.config.get_settings()
    nabla.config._settings = None
    s2 = nabla.config.get_settings()
    assert s1 is not s2
