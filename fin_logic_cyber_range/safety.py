# -*- coding: utf-8 -*-
"""The one door in and out of the range: nothing but a local mock may be reached.

Why a guard instead of a comment
--------------------------------
Every scenario in this package speaks HTTP to something, and the whole difference
between a laboratory and an incident is the value of ``urlsplit(url).hostname``.
A guard the caller can forget is not a guard, so :func:`ensure_local_url` is
called at three places on purpose - when a scenario is loaded, when the runner
builds a request, and when a gateway base URL is handed out. A scenario file that
names a real institution therefore fails at load time, in CI, before a socket is
opened.

What is allowed
---------------
======================  =====================================================
allowed                 why
======================  =====================================================
``127.0.0.1``, ``::1``,
``localhost``           the in-process harness binds here and nowhere else
``mock-gateway``,
``mock-secure-gateway`` the compose service names in ``deploy/cyber_range``;
                        resolving them is Docker's job on an ``internal``
                        network, and a name that is not on this list is not a
                        mock
``http``                ``https`` is not offered at all: the lab has no
                        certificate to speak of, and a TLS client would make
                        the traffic look like a real endpoint
ports ``1024..65535``   the unprivileged range a test harness may bind
======================  =====================================================

Everything else - a dotted domain, a public address, userinfo in the authority, a
path that is not absolute, a privileged port - raises :class:`SafetyViolation`,
which is a :class:`~ontology_builder.core.errors.DataContractError` and therefore
also a ``ValueError``: existing ``except ValueError`` blocks keep working while the
message still says which rule was broken.
"""
from __future__ import annotations

import os
from typing import NoReturn
from urllib.parse import urlsplit

from ontology_builder.core.errors import DataContractError

#: Hosts a request may name. Kept as an explicit allow-list, never as a pattern:
#: ``*.local`` or ``192.168.*`` would be a rule that grows, and the day it grows
#: to ``*`` nobody notices.
LOCAL_HOSTS = frozenset(
    {
        "127.0.0.1",
        "::1",
        "localhost",
        "mock-gateway",
        "mock-secure-gateway",
    }
)

#: The only address the harness is allowed to bind. ``0.0.0.0`` would publish the
#: mock to the LAN, which is exactly the thing this package exists not to do.
BIND_HOST = "127.0.0.1"

ALLOWED_SCHEMES = frozenset({"http"})
DEFAULT_PORTS = {"http": 80}
MIN_LOCAL_PORT = 1024
MAX_LOCAL_PORT = 65535

#: Name of the environment variable that lets the gateway bind ``0.0.0.0``.
#:
#: It exists for one deployment: ``deploy/cyber_range/docker-compose.yml`` publishes
#: a container port to ``127.0.0.1`` on the host, and Docker's port forwarding can
#: only reach a process bound to the container's own interface. The variable is set
#: in the image, never on a workstation, and defaults to off - so
#: ``ensure_bind_host("0.0.0.0")`` raising on a laptop is the normal case, and a
#: reader grepping for the string finds both the switch and this comment.
CONTAINER_BIND_ENV = "RANGE_ALLOW_CONTAINER_BIND"


def container_bind_allowed() -> bool:
    """Whether the container opt-in is set (exactly ``"1"``)."""
    return os.environ.get(CONTAINER_BIND_ENV, "").strip() == "1"


class SafetyViolation(DataContractError):
    """A target, bind address or scenario field that would leave the lab.

    Separate from a plain ``DataContractError`` so a caller (and the report) can
    say "this is the safety boundary talking, not a schema complaint" without
    matching on prose.
    """


def _reject(url: str, reason: str, **context: object) -> NoReturn:
    """Raise the boundary error with the URL and the broken rule attached."""
    raise SafetyViolation("refusing %r: %s" % (url, reason), target=url, **context)


def ensure_local_url(url: str) -> str:
    """Normalise ``url`` and prove it addresses a local mock.

    Args:
        url: candidate target, e.g. ``"http://127.0.0.1:8080/mock/v1/transfer"``.

    Returns:
        The canonical form ``http://<host>:<port><path>`` - host lower-cased and
        port always spelled out, so two spellings of one target compare equal and
        an access-log line is unambiguous.

    Raises:
        SafetyViolation: on a blank value, a scheme other than ``http``,
            credentials in the authority, a host outside :data:`LOCAL_HOSTS`, a
            port outside ``1024..65535``, or a relative path.
    """
    if not isinstance(url, str) or not url.strip():
        raise SafetyViolation("target must be a non-empty URL string", got=repr(url))
    raw = url.strip()
    parts = urlsplit(raw)
    scheme = parts.scheme.casefold()
    if scheme not in ALLOWED_SCHEMES:
        _reject(raw, "only http reaches a local mock", scheme=scheme)
    if parts.username or parts.password:
        _reject(raw, "credentials do not belong in a lab URL")
    host = (parts.hostname or "").casefold()
    if host not in LOCAL_HOSTS:
        _reject(
            raw,
            "host is not a loopback address or a compose service name",
            host=host,
            allowed=sorted(LOCAL_HOSTS),
        )
    try:
        port = parts.port
    except ValueError as exc:  # urlsplit accepts the text, int() does not
        _reject(raw, "port is not a number", error=str(exc))
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not MIN_LOCAL_PORT <= port <= MAX_LOCAL_PORT:
        _reject(raw, "port is outside the unprivileged lab range", port=port)
    path = parts.path or "/"
    if not path.startswith("/"):
        _reject(raw, "path must be absolute", path=path)
    if parts.query or parts.fragment:
        _reject(raw, "a mock route carries no query string or fragment")
    rendered = "[%s]" % host if ":" in host else host
    return "%s://%s:%d%s" % (scheme, rendered, port, path)


def is_local_url(url: str) -> bool:
    """:func:`ensure_local_url` as a predicate, for report columns."""
    try:
        ensure_local_url(url)
    except SafetyViolation:
        return False
    return True


def ensure_bind_host(host: str) -> str:
    """Prove ``host`` is an interface the harness may bind.

    Args:
        host: the address the caller wants to bind.

    Returns:
        The accepted address (``"127.0.0.1"``, or ``"0.0.0.0"`` inside a container
        with :data:`CONTAINER_BIND_ENV` set).

    Raises:
        SafetyViolation: for anything else - including ``localhost``, because a
            name resolves to whatever the resolver says and the bind address must
            not depend on a hosts file, and including ``0.0.0.0`` unless the
            container opt-in is set. ``0.0.0.0`` is only legitimate *inside* a
            container whose single published port is bound to ``127.0.0.1`` by
            ``deploy/cyber_range/docker-compose.yml``; on a workstation it would
            publish the mock to the LAN, so it needs an explicit, greppable switch.
    """
    value = host.strip() if isinstance(host, str) else ""
    if value == BIND_HOST:
        return value
    if value == "0.0.0.0" and container_bind_allowed():
        return value
    raise SafetyViolation(
        "the harness binds %s and nothing else" % BIND_HOST,
        host=host,
        container_opt_in=CONTAINER_BIND_ENV,
    )


def split_base_url(url: str) -> tuple[str, int]:
    """``(host, port)`` of an already-validated base URL, for ``http.client``.

    Raises:
        SafetyViolation: when ``url`` fails :func:`ensure_local_url`.
    """
    parts = urlsplit(ensure_local_url(url))
    return parts.hostname or BIND_HOST, parts.port or DEFAULT_PORTS["http"]
