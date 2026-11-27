"""Validation helpers for CoAP commands carried over a DTLS session.

A command is only executed when the session is established, the peer matches
the session identity, the command is allowed by its scope, the message is
inside the policy time window and its sequence number has not been executed
before.  Sequence numbers wrap around ``seq_modulus``, so replay detection is
performed on the wrapped value while execution state is kept per session.
"""

import json

DEFAULT_SEQ_MODULUS = 1 << 16


def _as_text(value):
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip(), 10)
        except (TypeError, ValueError):
            return None
    return None


def _as_number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return None
    return None


def _sessions(store):
    sessions = store.get("sessions", {})
    return sessions if isinstance(sessions, dict) else {}


def _session_id(session):
    if isinstance(session, dict):
        return _as_text(session.get("id")) or _as_text(session.get("session"))
    return _as_text(session)


def _session_record(store, session):
    sid = _session_id(session)
    if sid is None:
        return None
    record = _sessions(store).get(sid)
    return record if isinstance(record, dict) else None


def _policy(store):
    policy = store.get("policy", {})
    return policy if isinstance(policy, dict) else {}


def _seq_modulus(store):
    modulus = _as_int(_policy(store).get("seq_modulus", DEFAULT_SEQ_MODULUS))
    if modulus is None or modulus <= 0:
        modulus = DEFAULT_SEQ_MODULUS
    return modulus


def _seq_key(store, seq):
    """Normalize a sequence number onto the configured wrap period."""
    return seq % _seq_modulus(store)


def _seen_for(store, sid):
    seen_map = store.setdefault("seen", {})
    if not isinstance(seen_map, dict):
        seen_map = {}
        store["seen"] = seen_map
    seen = seen_map.get(sid)
    if not isinstance(seen, set):
        seen = set()
        seen_map[sid] = seen
    return seen


def _remember(store, sid, seq):
    _seen_for(store, sid).add(_seq_key(store, seq))
    last_map = store.setdefault("last_seq", {})
    if not isinstance(last_map, dict):
        last_map = {}
        store["last_seq"] = last_map
    last_map[sid] = seq


def _failure(reason, sid=None, seq=None, command=None):
    return {
        "ok": False,
        "executed": False,
        "reason": reason,
        "session": sid,
        "seq": seq,
        "command": command,
    }


def parse_message(raw):
    """Normalize a raw CoAP command message.

    The message must provide session, peer, seq, ts, cmd and scope. Numeric
    fields may be supplied as numbers or decimal strings.  Unrecognised keys
    are ignored.
    """
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, TypeError):
            raise ValueError("message is not valid JSON") from None
    elif isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            raise ValueError("message is not valid JSON") from None

    if not isinstance(raw, dict):
        raise ValueError("message must be an object")

    session = _as_text(raw.get("session"))
    peer = _as_text(raw.get("peer"))
    seq = _as_int(raw.get("seq"))
    ts = _as_number(raw.get("ts"))
    scope = _as_text(raw.get("scope"))
    command = _as_text(raw.get("cmd"))

    if session is None:
        raise ValueError("session is required")
    if peer is None:
        raise ValueError("peer is required")
    if seq is None or seq < 0:
        raise ValueError("seq must be a non-negative integer")
    if ts is None:
        raise ValueError("ts must be a number")
    if command is None:
        raise ValueError("cmd is required")
    if scope is None:
        raise ValueError("scope is required")

    return {
        "session": session,
        "peer": peer,
        "seq": seq,
        "ts": ts,
        "cmd": command,
        "scope": scope,
    }


def check_session(session, store):
    """Return True when the session exists and is established."""
    if not isinstance(store, dict):
        return False
    record = _session_record(store, session)
    if record is None:
        return False
    return bool(record.get("established", False))


def check_peer(msg, session):
    """Return True when the message peer matches the session peer."""
    if not isinstance(msg, dict) or not isinstance(session, dict):
        return False
    expected = _as_text(session.get("peer"))
    presented = _as_text(msg.get("peer"))
    if expected is None or presented is None:
        return False
    return expected == presented


def check_replay(store, session, seq):
    """Return True when the sequence number has not been executed yet.

    Deduplication is per session and follows the sequence wrap period, so a
    replayed message is rejected whatever timestamp it carries.
    """
    if not isinstance(store, dict):
        return False
    sid = _session_id(session)
    item = _as_int(seq)
    if sid is None or item is None or item < 0:
        return False
    key = _seq_key(store, item)
    for value in _seen_for(store, sid):
        existing = _as_int(value)
        if existing is not None and existing >= 0 and _seq_key(store, existing) == key:
            return False
    return True


def check_window(msg, now, policy):
    """Return True when ts falls inside the inclusive window around now."""
    if not isinstance(msg, dict) or not isinstance(policy, dict):
        return False
    ts = _as_number(msg.get("ts"))
    base = _as_number(now)
    window = _as_number(policy.get("window", 0))
    if ts is None or base is None or window is None or window < 0:
        return False
    return abs(ts - base) <= window


def check_scope(cmd, policy):
    """Return True when the command name is allowed by its scope."""
    if not isinstance(cmd, dict) or not isinstance(policy, dict):
        return False
    name = _as_text(cmd.get("name"))
    scope = _as_text(cmd.get("scope"))
    if name is None or scope is None:
        return False
    scopes = policy.get("scopes")
    if not isinstance(scopes, dict):
        return False
    allowed = scopes.get(scope)
    if isinstance(allowed, str):
        allowed = {allowed}
    if not isinstance(allowed, (set, frozenset, list, tuple)):
        return False
    return name in allowed


def handle(msg, store, now):
    """Validate, execute and record one CoAP command message."""
    if isinstance(msg, (str, bytes, bytearray)):
        try:
            msg = parse_message(msg)
        except ValueError:
            return _failure("message")
    if not isinstance(msg, dict):
        return _failure("message")
    if not isinstance(store, dict):
        return _failure("store")

    sid = _session_id(msg.get("session"))
    session = _session_record(store, sid)
    if not check_session(sid, store):
        return _failure("session", sid)

    if not check_peer(msg, session):
        return _failure("peer", sid)

    seq = _as_int(msg.get("seq"))
    ts = _as_number(msg.get("ts"))
    command = _as_text(msg.get("cmd"))
    scope = _as_text(msg.get("scope"))
    if seq is None or seq < 0 or ts is None or command is None or scope is None:
        return _failure("message", sid, seq)

    policy = _policy(store)

    if not check_scope({"name": command, "scope": scope}, policy):
        return _failure("scope", sid, seq, command)

    if not check_window({"ts": ts}, now, policy):
        return _failure("window", sid, seq, command)

    if not check_replay(store, sid, seq):
        return _failure("replay", sid, seq, command)

    record = {
        "session": sid,
        "peer": _as_text(msg.get("peer")),
        "seq": seq,
        "ts": ts,
        "cmd": command,
        "scope": scope,
    }
    executed = store.get("executed")
    if not isinstance(executed, list):
        executed = []
        store["executed"] = executed
    executed.append(record)
    _remember(store, sid, seq)

    return {
        "ok": True,
        "executed": True,
        "reason": "ok",
        "session": sid,
        "seq": seq,
        "command": command,
        "record": record,
    }


def coap_batch(messages, store, now):
    """Process a batch of CoAP messages, keeping per-device state separate."""
    if messages is None:
        items = []
    elif isinstance(messages, dict):
        items = [messages]
    elif isinstance(messages, (str, bytes, bytearray)):
        items = [messages]
    else:
        items = list(messages)

    results = []
    for item in items:
        results.append(handle(item, store, now))

    executed = sum(1 for result in results if result.get("executed"))
    return {
        "results": results,
        "executed": executed,
        "rejected": len(results) - executed,
    }
