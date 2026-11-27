import pytest

from engine.coap.check import (
    check_scope,
    check_session,
    coap_batch,
    handle,
    parse_message,
)


def _session(sid="s1", peer="dev-1", established=True):
    return {"id": sid, "peer": peer, "established": established}


def _store(*sessions):
    return {
        "sessions": {session["id"]: session for session in sessions},
        "policy": {
            "window": 30,
            "seq_modulus": 65536,
            "scopes": {
                "valve:write": {"open", "close"},
                "system": {"status"},
            },
        },
    }


def _message(session="s1", peer="dev-1", seq=1, ts=1000, cmd="open", scope="valve:write"):
    return {
        "session": session,
        "peer": peer,
        "seq": seq,
        "ts": ts,
        "cmd": cmd,
        "scope": scope,
    }


def test_parse_message_normalizes_fields_and_requires_command():
    raw = {
        "session": " s1 ",
        "peer": " dev-1 ",
        "seq": "7",
        "ts": "1000",
        "cmd": "open",
        "scope": "valve:write",
        "unused": "ignored",
    }

    message = parse_message(raw)

    assert message["session"] == "s1"
    assert message["peer"] == "dev-1"
    assert message["seq"] == 7
    assert message["ts"] == 1000
    assert message["cmd"] == "open"
    assert message["scope"] == "valve:write"
    assert "unused" not in message

    raw.pop("cmd")
    with pytest.raises(ValueError):
        parse_message(raw)


def test_check_session_requires_established_state():
    store = _store(_session("s1", "dev-1", established=False))

    assert check_session("s1", store) is False
    assert check_session("missing", store) is False


def test_handle_deduplicates_adjacent_sequence():
    store = _store(_session())
    message = _message(seq=7)

    first = handle(message, store, 1000)
    second = handle(dict(message), store, 1000)

    assert first["ok"] is True
    assert first["executed"] is True
    assert second["ok"] is False
    assert second["executed"] is False
    assert second["reason"] == "replay"
    assert len(store["executed"]) == 1


def test_check_scope_enforces_policy_scope():
    policy = {"scopes": {"valve:write": {"open", "close"}}}

    assert check_scope({"name": "open", "scope": "valve:write"}, policy) is True
    assert check_scope({"name": "open", "scope": "admin:write"}, policy) is False
    assert check_scope({"name": "delete", "scope": "valve:write"}, policy) is False


def test_batch_keeps_devices_independent():
    store = _store(
        _session("s1", "dev-1"),
        _session("s2", "dev-2"),
    )
    messages = [
        _message("s1", "dev-1", seq=1, ts=1000),
        _message("s2", "dev-2", seq=1, ts=1000),
    ]

    outcome = coap_batch(messages, store, 1000)

    assert outcome["executed"] == 2
    assert outcome["rejected"] == 0
    assert [result["ok"] for result in outcome["results"]] == [True, True]
    assert [result["session"] for result in outcome["results"]] == ["s1", "s2"]