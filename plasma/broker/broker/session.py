"""broker.session — the authenticated-session state machine.

Layering: this module owns *state transitions only*. It knows nothing about TLS,
policy or capabilities. A handshake backend supplies an observed peer
fingerprint; the session refuses to reach AUTHENTICATED unless that fingerprint
equals the pinned one. Execution is reachable only through
AUTHENTICATED -> AUTHORIZED -> EXECUTING, so there is no "approximately
authenticated" path and no way to execute before authorization.

    DISCONNECTED -> CONNECTED -> AUTHENTICATING -> AUTHENTICATED
                 -> AUTHORIZED -> EXECUTING -> COMPLETED | FAILED
                                              | OUTCOME_UNKNOWN | CANCELLED
    any violation -> CLOSED
"""
from __future__ import annotations

from enum import Enum


class State(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CANCELLED = "cancelled"
    CLOSED = "closed"


_LEGAL = {
    State.DISCONNECTED: {State.CONNECTED, State.CLOSED},
    State.CONNECTED: {State.AUTHENTICATING, State.CLOSED},
    State.AUTHENTICATING: {State.AUTHENTICATED, State.CLOSED},
    State.AUTHENTICATED: {State.AUTHORIZED, State.CLOSED},
    State.AUTHORIZED: {State.EXECUTING, State.CLOSED},
    State.EXECUTING: {State.COMPLETED, State.FAILED, State.OUTCOME_UNKNOWN, State.CANCELLED, State.CLOSED},
    State.COMPLETED: {State.CLOSED},
    State.FAILED: {State.CLOSED},
    State.OUTCOME_UNKNOWN: {State.CLOSED},
    State.CANCELLED: {State.CLOSED},
    State.CLOSED: set(),
}


class ProtocolError(Exception):
    """A protocol or policy violation. The session is forced to CLOSED."""


class Session:
    def __init__(self, pinned_fingerprint: str, session_id: str = ""):
        self.pinned_fingerprint = pinned_fingerprint
        self.session_id = session_id
        self.state = State.DISCONNECTED
        self.peer_fingerprint = ""

    def _to(self, target: State) -> None:
        if target not in _LEGAL[self.state]:
            self.state = State.CLOSED
            raise ProtocolError(f"illegal_transition:{self.state.value}->{target.value}")
        self.state = target

    def connected(self) -> None:
        self._to(State.CONNECTED)

    def begin_auth(self) -> None:
        self._to(State.AUTHENTICATING)

    def authenticated(self, peer_fingerprint: str) -> None:
        """Reach AUTHENTICATED only if the live peer matches the pin."""
        if self.state is not State.AUTHENTICATING:
            self.state = State.CLOSED
            raise ProtocolError(f"illegal_transition:{self.state.value}->authenticated")
        if not peer_fingerprint or peer_fingerprint != self.pinned_fingerprint:
            self.state = State.CLOSED
            raise ProtocolError("identity_mismatch")
        self.peer_fingerprint = peer_fingerprint
        self.state = State.AUTHENTICATED

    def authorize(self, allowed: bool) -> None:
        if self.state is not State.AUTHENTICATED:
            self.state = State.CLOSED
            raise ProtocolError(f"illegal_transition:{self.state.value}->authorized")
        if not allowed:
            self.state = State.CLOSED
            raise ProtocolError("not_authorized")
        self.state = State.AUTHORIZED

    def begin_execute(self) -> None:
        self._to(State.EXECUTING)

    def finish(self, outcome: State) -> None:
        if outcome not in (State.COMPLETED, State.FAILED, State.OUTCOME_UNKNOWN, State.CANCELLED):
            raise ProtocolError(f"invalid_outcome:{outcome}")
        self._to(outcome)

    def close(self) -> None:
        self.state = State.CLOSED
