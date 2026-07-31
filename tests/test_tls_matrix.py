"""TLS acceptance matrix and JARM.

Offline throughout: the network half is one small function (`_one_hello`),
so everything else is tested by feeding `HelloOutcome`s straight to the pure
summarizers. Hello construction is verified by parsing the bytes back.
"""
from __future__ import annotations

import pytest

from lodan.probes.tls_matrix import (
    JARM_HELLOS,
    MATRIX_HELLOS,
    HelloOutcome,
    jarm_from_outcomes,
    summarize_matrix,
)
from lodan.probes.tls_parser import (
    EXT_SUPPORTED_VERSIONS,
    HS_CLIENT_HELLO,
    build_client_hello,
)


def _accepted(name: str, version: int, cipher: int, extensions=()) -> HelloOutcome:
    return HelloOutcome(name, accepted=True, version=version, cipher=cipher,
                        extensions=tuple(extensions))


def _refused(name: str) -> HelloOutcome:
    return HelloOutcome(name, accepted=False)


# --- hello construction ------------------------------------------------------

def test_matrix_has_the_documented_connection_count() -> None:
    """Six, not eleven — the weak-cipher question is asked with one hello."""
    assert len(MATRIX_HELLOS) == 6
    assert [s.name for s in MATRIX_HELLOS] == [
        "tls1.0", "tls1.1", "tls1.2", "tls1.3", "weak-ciphers", "static-rsa",
    ]


def test_legacy_version_hellos_omit_supported_versions() -> None:
    """A TLS 1.0-only server predates the extension and negotiates off the
    legacy field; sending supported_versions would ask the wrong question."""
    by_name = {s.name: s for s in MATRIX_HELLOS}
    assert by_name["tls1.0"].include_supported_versions is False
    assert by_name["tls1.0"].legacy_version == 0x0301
    assert by_name["tls1.1"].legacy_version == 0x0302
    ch = build_client_hello(by_name["tls1.0"])
    assert EXT_SUPPORTED_VERSIONS not in ch.extensions


def test_modern_version_hellos_carry_supported_versions() -> None:
    by_name = {s.name: s for s in MATRIX_HELLOS}
    ch = build_client_hello(by_name["tls1.3"])
    assert EXT_SUPPORTED_VERSIONS in ch.extensions
    assert by_name["tls1.3"].supported_versions == (0x0304,)


def test_every_hello_builds_a_well_formed_record() -> None:
    for spec in (*MATRIX_HELLOS, *JARM_HELLOS):
        ch = build_client_hello(spec)
        assert ch.record[0] == 22                     # handshake content type
        assert ch.record[5] == HS_CLIENT_HELLO
        # Record length header must match the actual payload.
        declared = int.from_bytes(ch.record[3:5], "big")
        assert declared == len(ch.record) - 5


def test_default_hello_is_unchanged_by_parameterization() -> None:
    """JA3 is a function of these bytes; the no-arg path must not move."""
    a = build_client_hello()
    b = build_client_hello(None)
    assert a.ja3 == b.ja3
    assert a.ciphers == b.ciphers
    assert a.extensions == b.extensions


# --- matrix summarization ----------------------------------------------------

def test_accepted_versions_require_the_negotiated_version_to_match() -> None:
    """A server answering a 1.0 hello with 1.2 has ignored the ask, not
    accepted it — counting that would report legacy TLS on modern servers."""
    result = summarize_matrix([
        _accepted("tls1.0", 0x0303, 0xC030),      # answered, but with 1.2
        _accepted("tls1.1", 0x0302, 0xC014),      # genuinely accepted 1.1
        _accepted("tls1.2", 0x0303, 0xC030),
        _refused("tls1.3"),
    ])
    assert "TLS 1.0" not in result.accepted_versions
    assert "TLS 1.1" in result.accepted_versions
    assert "TLS 1.2" in result.accepted_versions
    assert "TLS 1.3" in result.rejected_versions
    assert "TLS 1.0" in result.rejected_versions


def test_modern_server_accepts_only_12_and_13() -> None:
    result = summarize_matrix([
        _refused("tls1.0"), _refused("tls1.1"),
        _accepted("tls1.2", 0x0303, 0xC030), _accepted("tls1.3", 0x0304, 0x1301),
        _refused("weak-ciphers"), _refused("static-rsa"),
    ])
    assert result.accepted_versions == ("TLS 1.2", "TLS 1.3")
    assert result.weak_cipher is None
    assert result.weak_families == ()
    assert result.accepts_static_rsa is False


def test_weak_cipher_is_labelled_and_family_tagged() -> None:
    result = summarize_matrix([_accepted("weak-ciphers", 0x0303, 0x000A)])
    assert result.weak_cipher == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert result.weak_families == ("3des",)


def test_null_cipher_family_detected() -> None:
    result = summarize_matrix([_accepted("weak-ciphers", 0x0303, 0x0002)])
    assert "null" in result.weak_families


def test_anon_cipher_is_in_two_families() -> None:
    """0x0018 is both anonymous DH and RC4 — both are worth reporting."""
    result = summarize_matrix([_accepted("weak-ciphers", 0x0303, 0x0018)])
    assert set(result.weak_families) == {"anon", "rc4"}


def test_unknown_weak_cipher_falls_back_to_hex() -> None:
    result = summarize_matrix([_accepted("weak-ciphers", 0x0303, 0xDEAD)])
    assert result.weak_cipher == "0xdead"


def test_static_rsa_acceptance_is_recorded() -> None:
    result = summarize_matrix([_accepted("static-rsa", 0x0303, 0x0035)])
    assert result.accepts_static_rsa is True


def test_refused_static_rsa_means_forward_secrecy_only() -> None:
    assert summarize_matrix([_refused("static-rsa")]).accepts_static_rsa is False


def test_summary_is_json_serializable() -> None:
    import json
    result = summarize_matrix([_accepted("weak-ciphers", 0x0303, 0x000A)])
    json.dumps(result.as_dict())


def test_empty_outcome_list_is_harmless() -> None:
    result = summarize_matrix([])
    assert result.accepted_versions == ()
    assert result.weak_cipher is None


# --- JARM --------------------------------------------------------------------

def test_jarm_uses_ten_hellos() -> None:
    assert len(JARM_HELLOS) == 10


def test_jarm_is_62_characters() -> None:
    outcomes = [_accepted(f"j{i}", 0x0303, 0xC030, (0, 11, 35)) for i in range(1, 11)]
    jarm = jarm_from_outcomes(outcomes)
    assert jarm is not None
    assert len(jarm) == 62


def test_jarm_is_deterministic() -> None:
    outcomes = [_accepted(f"j{i}", 0x0303, 0xC030, (0, 11)) for i in range(1, 11)]
    assert jarm_from_outcomes(outcomes) == jarm_from_outcomes(list(outcomes))


def test_jarm_differs_when_cipher_selection_differs() -> None:
    a = [_accepted(f"j{i}", 0x0303, 0xC030, (0,)) for i in range(1, 11)]
    b = [_accepted(f"j{i}", 0x0303, 0xC02F, (0,)) for i in range(1, 11)]
    assert jarm_from_outcomes(a) != jarm_from_outcomes(b)


def test_jarm_differs_when_extensions_differ() -> None:
    """The trailing 32 chars are the extension digest — same ciphers, different
    extensions must still separate two servers."""
    a = [_accepted(f"j{i}", 0x0303, 0xC030, (0, 11)) for i in range(1, 11)]
    b = [_accepted(f"j{i}", 0x0303, 0xC030, (0, 16)) for i in range(1, 11)]
    ja, jb = jarm_from_outcomes(a), jarm_from_outcomes(b)
    assert ja is not None and jb is not None
    assert ja[:30] == jb[:30]      # same cipher/version answers
    assert ja[30:] != jb[30:]      # different extension digest


def test_jarm_encodes_refusals_as_zero_groups() -> None:
    outcomes = [_refused(f"j{i}") for i in range(1, 10)]
    outcomes.append(_accepted("j10", 0x0303, 0xC030, (0,)))
    jarm = jarm_from_outcomes(outcomes)
    assert jarm is not None
    assert jarm[:27] == "0" * 27          # nine refused hellos
    assert jarm[27:30] != "000"


def test_jarm_is_none_when_nothing_answered() -> None:
    """An all-zero JARM is indistinguishable from 'refuses everything', so a
    value that means nothing is worse than no value."""
    assert jarm_from_outcomes([_refused(f"j{i}") for i in range(1, 11)]) is None
    assert jarm_from_outcomes([]) is None


@pytest.mark.parametrize("version", [0x0301, 0x0302, 0x0303, 0x0304])
def test_jarm_version_codes_are_distinct(version: int) -> None:
    outcomes = [_accepted(f"j{i}", version, 0xC030, (0,)) for i in range(1, 11)]
    jarm = jarm_from_outcomes(outcomes)
    assert jarm is not None and jarm[2] != "0"
