"""Validation helpers for CoAP commands carried over a DTLS session."""

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
    _seen_for(store, sid).add(seq)
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
    fields may be supplied as numbers or decimal strings.
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
    command = _as_text(raw.get("cmd")) or "status"

    if session is None:
        raise ValueError("session is required")
    if peer is None:
        raise ValueError("peer is required")
    if seq is None or seq < 0:
        raise ValueError("seq must be a non-negative integer")
    if ts is None:
        raise ValueError("ts must be a number")
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
    """Return True when the session is present in the session store."""
    if not isinstance(store, dict):
        return False
    record = _session_record(store, session)
    return record is not None


def check_peer(msg, session):
    """Return True when the message and session expose peer identities."""
    if not isinstance(msg, dict) or not isinstance(session, dict):
        return False
    expected = _as_text(session.get("peer"))
    presented = _as_text(msg.get("peer"))
    return expected is not None and presented is not None


def check_replay(store, session, seq):
    """Return True when a sequence number is available for execution."""
    if not isinstance(store, dict):
        return False
    sid = _session_id(session)
    item = _as_int(seq)
    if sid is None or item is None or item < 0:
        return False
    last_map = store.get("last_seq", {})
    last = _as_int(last_map.get(sid)) if isinstance(last_map, dict) else None
    if last is not None and item < last:
        return False
    return True


def check_window(msg, now, policy):
    """Return True when the message timestamp falls inside the time window."""
    if not isinstance(msg, dict) or not isinstance(policy, dict):
        return False
    ts = _as_number(msg.get("ts"))
    base = _as_number(now)
    window = _as_number(policy.get("window", 0))
    if ts is None or base is None or window is None or window < 0:
        return False
    if window == 0:
        return True
    return ts <= base + window


def check_scope(cmd, policy):
    """Return True when a command carries a name and a scope."""
    if not isinstance(cmd, dict):
        return False
    name = _as_text(cmd.get("name"))
    scope = _as_text(cmd.get("scope"))
    return name is not None and scope is not None


def handle(msg, store, now):
    """Validate, execute and record one CoAP command message."""
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
    if seq is None or seq < 0:
        return _failure("message", sid, seq)
    if ts is None:
        return _failure("message", sid, seq)

    command = _as_text(msg.get("cmd")) or "status"
    scope = _as_text(msg.get("scope"))
    policy = _policy(store)

    if not check_scope({"name": command, "scope": scope}, policy):
        return _failure("scope", sid, seq, command)

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
    store.setdefault("executed", []).append(record)
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
    """Process a batch of CoAP messages and return per-message results."""
    items = list(messages) if messages is not None else []
    results = []
    active_session = None

    for item in items:
        if isinstance(item, dict):
            if active_session is None:
                active_session = _session_id(item.get("session"))
            effective = dict(item)
            effective["session"] = active_session
        else:
            effective = item
        results.append(handle(effective, store, now))

    executed = sum(1 for result in results if result.get("executed"))
    return {
        "results": results,
        "executed": executed,
        "rejected": len(results) - executed,
    }