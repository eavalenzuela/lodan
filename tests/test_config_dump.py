from __future__ import annotations

import tomllib

from lodan.config import (
    Config,
    WorkspaceBlock,
    default_config_toml,
    dump_config_toml,
)


def _cfg(**ws) -> Config:
    base = {"name": "w", "authorized_ranges": ["10.0.0.0/24"]}
    base.update(ws)
    return Config(workspace=WorkspaceBlock(**base))


def test_default_has_expected_literals() -> None:
    t = default_config_toml("home-lab", ["10.0.0.0/24", "192.168.1.0/24"])
    assert '"10.0.0.0/24"' in t
    assert '"192.168.1.0/24"' in t
    assert 'backend = "auto"' in t
    assert "# [retention]" in t  # retention stays commented while unset


def test_default_roundtrips() -> None:
    c = Config.model_validate(tomllib.loads(default_config_toml("w", ["10.0.0.0/24"])))
    assert c.workspace.name == "w"
    assert c.scan.backend == "auto"
    assert c.workspace.authorized_ranges == ["10.0.0.0/24"]


def test_retention_appended_to_default_still_parses() -> None:
    # test_retention.py appends a real [retention] table to the default
    # (commented) output; that must remain valid TOML.
    t = default_config_toml("w", ["10.0.0.0/24"])
    tomllib.loads(t + "\n[retention]\nkeep_last_n = 1\n")


def test_dump_roundtrips_quotes_and_newlines() -> None:
    c = _cfg(
        cloud_provider_allowed=True,
        cloud_provider_justification='a "quoted"\nsecond line',
    )
    c.retention.keep_last_n = 24
    c2 = Config.model_validate(tomllib.loads(dump_config_toml(c)))
    assert c2.workspace.cloud_provider_justification == 'a "quoted"\nsecond line'
    assert c2.retention.keep_last_n == 24
    assert c2.retention.keep_monthly is None


def test_dump_roundtrips_astral_unicode() -> None:
    # Non-BMP chars (emoji, CJK Ext-B) must stay literal UTF-8, not surrogate
    # \uXXXX escapes that tomllib rejects as non-scalar.
    c = _cfg(cloud_provider_justification="lab 🔬 检测 𠀀")
    text = dump_config_toml(c)
    c2 = Config.model_validate(tomllib.loads(text))
    assert c2.workspace.cloud_provider_justification == "lab 🔬 检测 𠀀"


def test_dump_renders_real_retention_when_set() -> None:
    c = _cfg()
    c.retention.keep_monthly = 6
    t = dump_config_toml(c)
    assert "# [retention]" not in t
    assert "[retention]" in t
    assert "keep_monthly = 6" in t
    assert "keep_last_n" not in t  # unset knob omitted


def test_notify_commented_while_disabled() -> None:
    t = default_config_toml("w", ["10.0.0.0/24"])
    assert "# [notify]" in t          # discoverable but inert
    assert "[notify]\n" not in t       # no active table
    # Still parses, and notify stays at defaults (disabled).
    c = Config.model_validate(tomllib.loads(t))
    assert c.notify.enabled is False


def test_notify_renders_real_table_when_set() -> None:
    c = _cfg()
    c.notify.webhook_url = "https://hooks.example.com/lodan"
    t = dump_config_toml(c)
    assert "# [notify]" not in t
    assert "[notify]" in t
    assert 'webhook_url = "https://hooks.example.com/lodan"' in t
    # Round-trips back to an enabled webhook.
    c2 = Config.model_validate(tomllib.loads(t))
    assert c2.notify.webhook_enabled is True
    assert c2.notify.webhook_url == "https://hooks.example.com/lodan"


def test_config_dump_method_matches_module_fn() -> None:
    c = _cfg()
    assert c.dump() == dump_config_toml(c)
