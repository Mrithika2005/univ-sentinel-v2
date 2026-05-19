"""
SENTINEL SDK — Python Agent  v3.2
==================================
Changes from v3.1:
  • PSUTIL VITALS FIX: _emit_vitals() now always reads live psutil values
    for cpuPercent, diskUsedPercent, diskUsedBytes, memoryTotalBytes on
    every vitals emit — matches the requested context fields exactly.

  • PER-REQUEST TRACE IDs: Every incoming HTTP request (Flask, FastAPI,
    Django) gets a fresh trace_id generated at the gateway layer and
    stored in a threading.local() context so every downstream call
    (DB queries, outbound HTTP, queue ops) in the same thread inherits
    the same trace_id automatically. This replaces the heuristic ±500ms
    Gantt matching with an exact WHERE trace_id = X join.

  • SESSION TRACKING: Every request is correlated with a unique
    sessionId (from cookie/header or newly generated). The SDK maintains
    an in-process set of active session IDs so activeUsers can be
    reported on every request log. Session start/end events are emitted
    to the OBSERVABILITY layer. All data goes into the context JSON
    column — zero schema changes.

  • MONGODB PATCH: Added _patch_mongodb() for PyMongo / Motor — patches
    Collection.find, insert_one, insert_many, update_one, update_many,
    delete_one, delete_many, aggregate with duration + slow-query logging.

  • DJANGO MIDDLEWARE: Added django_middleware() — a standard Django
    MIDDLEWARE class with the same per-request traceId + session logic.

  • ZERO-CONFIG AUTO-HOOK: The module exports _auto_hook() which is
    called automatically when SENTINEL_AUTO=1 is set. For fully
    zero-config operation use the sentinel_autoload.py sitecustomize
    companion (see autoload/sentinel_autoload.py).

  • All v3.1 fixes preserved unchanged.
"""

from __future__ import annotations

import base64
import builtins
import datetime
import functools
import inspect
import json
import logging
import os
import re as _re
import secrets
import signal
import ssl
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

# ── Thread-local request context ─────────────────────────────────────────────
# Stores the current request's trace_id, session_id, user_id so every
# downstream emit in the same thread inherits them automatically.

_request_ctx = threading.local()


def _get_trace_id() -> str:
    return getattr(_request_ctx, 'trace_id', 'untracked')

def _get_session_id() -> Optional[str]:
    return getattr(_request_ctx, 'session_id', None)

def _get_user_id() -> Optional[str]:
    return getattr(_request_ctx, 'user_id', None)

def _set_request_ctx(trace_id: str, session_id: Optional[str], user_id: Optional[str]) -> None:
    _request_ctx.trace_id  = trace_id
    _request_ctx.session_id = session_id
    _request_ctx.user_id   = user_id

def _clear_request_ctx() -> None:
    _request_ctx.trace_id   = 'untracked'
    _request_ctx.session_id = None
    _request_ctx.user_id    = None


# ── Session registry ──────────────────────────────────────────────────────────
# Tracks active sessions across all threads. Thread-safe with a lock.
# Stores: { session_id: {"start": float, "last_seen": float, "user_id": str|None} }

class _SessionRegistry:
    _SESSION_TIMEOUT_S = 30 * 60  # 30 minutes idle = session expired

    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock     = threading.Lock()

    def touch(self, session_id: str, user_id: Optional[str] = None) -> bool:
        """Mark session as active. Returns True if this is a new session."""
        with self._lock:
            is_new = session_id not in self._sessions
            if is_new:
                self._sessions[session_id] = {
                    'start':     time.time(),
                    'last_seen': time.time(),
                    'user_id':   user_id,
                }
            else:
                self._sessions[session_id]['last_seen'] = time.time()
                if user_id:
                    self._sessions[session_id]['user_id'] = user_id
            return is_new

    def end(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Explicitly end a session. Returns session info or None."""
        with self._lock:
            return self._sessions.pop(session_id, None)

    def active_count(self) -> int:
        self._reap()
        with self._lock:
            return len(self._sessions)

    def active_sessions(self) -> List[str]:
        self._reap()
        with self._lock:
            return list(self._sessions.keys())

    def _reap(self) -> None:
        """Remove sessions idle longer than SESSION_TIMEOUT_S."""
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, info in self._sessions.items()
                if now - info['last_seen'] > self._SESSION_TIMEOUT_S
            ]
            for sid in expired:
                del self._sessions[sid]

    def get_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get(session_id)


_sessions = _SessionRegistry()


# ── Optional imports (graceful) ───────────────────────────────────────────────

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import httpx as _httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import sqlalchemy as _sa
    from sqlalchemy import event as _sa_event
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    import psycopg2 as _psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    import neo4j as _neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    import redis as _redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    import psutil as _psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import pymongo as _pymongo
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False

try:
    import celery as _celery
    from celery import signals as _celery_signals
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False

try:
    import pika as _pika
    HAS_PIKA = True
except ImportError:
    HAS_PIKA = False

try:
    import aiokafka as _aiokafka
    HAS_AIOKAFKA = True
except ImportError:
    HAS_AIOKAFKA = False


# ── Layer & Level constants ───────────────────────────────────────────────────

class LogLayer:
    PRESENTATION   = 'presentation'
    API_GATEWAY    = 'api_gateway'
    BUSINESS_LOGIC = 'business_logic'
    DATA_ACCESS    = 'data_access'
    SERVICE        = 'service'
    SECURITY       = 'security'
    OBSERVABILITY  = 'observability'
    INFRASTRUCTURE = 'infrastructure'
    DOMAIN         = 'domain'


class LogLevel:
    DEBUG = 'DEBUG'
    INFO  = 'INFO'
    WARN  = 'WARN'
    ERROR = 'ERROR'
    FATAL = 'FATAL'


_LEVEL_ORDER: Dict[str, int] = {
    LogLevel.DEBUG: 0, LogLevel.INFO: 1, LogLevel.WARN: 2,
    LogLevel.ERROR: 3, LogLevel.FATAL: 4,
}

# ── PII masking ───────────────────────────────────────────────────────────────

_PII_PATTERNS: List[Tuple[_re.Pattern, str]] = [
    (_re.compile(r'\b(?:\d[ -]?){13,16}\b'),                                                         '[CARD]'),
    (_re.compile(r'\b[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/_-]{20,}\b'),             '[JWT]'),
    (_re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', _re.I),                                         'Bearer [TOKEN]'),
    (_re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),                         '[EMAIL]'),
    (_re.compile(r'(password|passwd|pwd|secret|token|api_?key|auth)["\'\s:=]+["\']?[^\s"\'`,;}{)\]]+["\']?', _re.I), r'\1=[REDACTED]'),
    (_re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                                          '[SSN]'),
    (_re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),                      '[PHONE]'),
]

_REDACT_KEYS = _re.compile(
    r'password|passwd|pwd|secret|token|api_?key|auth|credential|private|authorization',
    _re.I,
)


def mask_pii(value: str) -> str:
    if not isinstance(value, str):
        return value
    for pattern, replacement in _PII_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def mask_context(obj: Any, depth: int = 0) -> Any:
    if depth > 5:
        return obj
    if isinstance(obj, str):
        return mask_pii(obj)
    if isinstance(obj, (list, tuple)):
        masked = [mask_context(v, depth + 1) for v in obj]
        return type(obj)(masked)
    if not isinstance(obj, dict):
        return obj
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        if _REDACT_KEYS.search(str(k)):
            out[k] = '[REDACTED]'
        elif isinstance(v, dict):
            out[k] = mask_context(v, depth + 1)
        elif isinstance(v, (list, tuple)):
            out[k] = mask_context(v, depth + 1)
        elif isinstance(v, str):
            out[k] = mask_pii(v)
        else:
            out[k] = v
    return out


# ── W3C traceparent helpers ───────────────────────────────────────────────────

def _gen_8hex() -> str:
    return secrets.token_hex(8)


def _gen_16hex() -> str:
    return secrets.token_hex(16)


_TRACE_ID_RE = _re.compile(r'^[0-9a-f]{32}$')
_SPAN_ID_RE  = _re.compile(r'^[0-9a-f]{16}$')


def build_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    tid = (trace_id or '').ljust(32, '0')[:32]
    sid = (span_id  or '').ljust(16, '0')[:16]
    return f'00-{tid}-{sid}-{"01" if sampled else "00"}'


def parse_traceparent(header: str) -> Optional[Dict[str, Any]]:
    if not header or not isinstance(header, str):
        return None
    parts = header.split('-')
    if len(parts) != 4 or parts[0] != '00':
        return None
    trace_id, span_id, flags = parts[1], parts[2], parts[3]
    if not _TRACE_ID_RE.match(trace_id) or not _SPAN_ID_RE.match(span_id):
        return None
    return {'trace_id': trace_id, 'span_id': span_id, 'sampled': flags == '01'}


# ── Layer inference ───────────────────────────────────────────────────────────

_LAYER_PATTERNS: List[Tuple[_re.Pattern, str]] = [
    (_re.compile(r'auth|jwt|token|oauth|permission|acl|rbac|guard|firewall|waf|encrypt|decrypt|password|credential|session|csrf|cors', _re.I), LogLayer.SECURITY),
    (_re.compile(r'repo|repository|dao|database|db|query|migration|schema|cache|redis|mongo|postgres|sql|neo4j|orm|entity|store|persist|storage', _re.I), LogLayer.DATA_ACCESS),
    (_re.compile(r'controller|router|route|middleware|gateway|proxy|handler|endpoint|api|rest|graphql|grpc|webhook|interceptor|view', _re.I), LogLayer.API_GATEWAY),
    (_re.compile(r'service|saga|aggregate|domain|policy|rule|event|command|workflow|process|pricing|discount|fraud|risk|consent', _re.I), LogLayer.DOMAIN),
    (_re.compile(r'infra|worker|job|cron|queue|kafka|rabbit|bull|pubsub|container|health|monitor|metric|cpu|memory|disk|celery', _re.I), LogLayer.INFRASTRUCTURE),
    (_re.compile(r'trace|span|log|alert|metric|telemetry|observer|slo|sla|alarm', _re.I), LogLayer.OBSERVABILITY),
    (_re.compile(r'component|page|ui|render|form|modal|widget|screen|layout|theme|template', _re.I), LogLayer.PRESENTATION),
]

_AUTH_PATH_RE = _re.compile(r'/(login|logout|auth|token|oauth|signin|signup|refresh|verify)', _re.I)
_BOT_UA_RE    = _re.compile(r'bot|crawl|spider|scraper|curl|wget|python-requests|go-http|aiohttp', _re.I)
_MIGRATION_RE = _re.compile(r'^\s*(CREATE|DROP|ALTER)\s+TABLE', _re.I)


def infer_layer(name: str) -> str:
    for pattern, layer in _LAYER_PATTERNS:
        if pattern.search(name):
            return layer
    return LogLayer.BUSINESS_LOGIC


# ── LogRecord ─────────────────────────────────────────────────────────────────

class LogRecord:
    __slots__ = (
        'message', 'level', 'layer', 'timestamp',
        'record_id', 'trace_id', 'span_id',
        'service', 'env', 'context',
        'host', 'version', 'request_id', 'tenant_id', 'is_audit',
    )

    def __init__(
        self,
        message:    str,
        layer:      str = LogLayer.BUSINESS_LOGIC,
        level:      str = LogLevel.INFO,
        service:    str = 'unknown-python-service',
        context:    Optional[Dict[str, Any]] = None,
        trace_id:   str = 'untracked',
        span_id:    Optional[str] = None,
        request_id: str = '',
        tenant_id:  str = '',
        is_audit:   bool = False,
    ):
        self.message    = message
        self.layer      = layer
        self.level      = level
        self.service    = service
        self.timestamp  = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.record_id  = str(uuid.uuid4())
        self.trace_id   = trace_id
        self.span_id    = span_id or _gen_8hex()
        self.env        = os.getenv('ENV', os.getenv('PYTHON_ENV', 'development'))
        self.host       = os.getenv('HOSTNAME', os.getenv('HOST', socket.gethostname()))
        self.version    = os.getenv('SERVICE_VERSION', os.getenv('APP_VERSION', '0.0.0'))
        self.request_id = request_id
        self.tenant_id  = tenant_id
        self.is_audit   = is_audit
        self.context    = context or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp':  self.timestamp,
            'record_id':  self.record_id,
            'trace_id':   self.trace_id,
            'span_id':    self.span_id,
            'service':    self.service,
            'env':        self.env,
            'host':       self.host,
            'version':    self.version,
            'request_id': self.request_id,
            'tenant_id':  self.tenant_id,
            'layer':      self.layer,
            'level':      self.level,
            'message':    self.message,
            'context':    json.dumps(self.context or {}),
        }

    def __str__(self) -> str:
        _colors = {
            LogLevel.DEBUG: '\033[36m', LogLevel.INFO:  '\033[92m',
            LogLevel.WARN:  '\033[93m', LogLevel.ERROR: '\033[91m',
            LogLevel.FATAL: '\033[95m',
        }
        reset = '\033[0m'
        c = _colors.get(self.level, '\033[92m')
        return f'{c}[{self.timestamp}] [{self.layer.upper()}] [{self.level}] {self.message}{reset}'


# ── Disk buffer ───────────────────────────────────────────────────────────────

class _DiskBuffer:
    def __init__(self, directory: str, max_mb: int):
        self._dir       = directory
        self._max_bytes = max_mb * 1024 * 1024
        self._file      = os.path.join(directory, 'sentinel-buffer.ndjson')
        self._lock      = threading.Lock()
        os.makedirs(directory, exist_ok=True)

    def write(self, records: List[LogRecord]) -> None:
        with self._lock:
            try:
                rows = '\n'.join(json.dumps(r.to_dict()) for r in records) + '\n'
                current = self._size()
                if current + len(rows.encode()) >= self._max_bytes:
                    self._rotate()
                with open(self._file, 'a', encoding='utf-8') as f:
                    f.write(rows)
            except Exception:
                pass

    def drain(self) -> List[str]:
        with self._lock:
            try:
                if not os.path.exists(self._file):
                    return []
                with open(self._file, 'r', encoding='utf-8') as f:
                    lines = [line for line in f.read().splitlines() if line.strip()]
                os.unlink(self._file)
                return lines
            except Exception:
                return []

    def _size(self) -> int:
        try:
            return os.path.getsize(self._file)
        except Exception:
            return 0

    def _rotate(self) -> None:
        try:
            with open(self._file, 'r', encoding='utf-8') as f:
                lines = [l for l in f.read().splitlines() if l]
            kept = lines[len(lines) // 2:]
            with open(self._file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(kept) + '\n')
        except Exception:
            pass


# ── ClickHouse batch writer ───────────────────────────────────────────────────

class _ClickHouseWriter:
    def __init__(self, cfg: Dict[str, Any]):
        self._host       = cfg.get('clickhouse_host',     'http://localhost:8123')
        self._db         = cfg.get('clickhouse_database', 'sentinel')
        self._table      = cfg.get('clickhouse_table',    'logs')
        self._user       = cfg.get('clickhouse_user',     '')
        self._password   = cfg.get('clickhouse_password', '')
        self._batch      = cfg.get('batch_size',          50)
        self._debug      = cfg.get('debug',               False)
        self._audit_path = cfg.get(
            'audit_log_path',
            os.path.join(cfg.get('disk_buffer_dir', '/tmp/sentinel'), 'sentinel-audit.ndjson'),
        )
        self._queue:  List[LogRecord] = []
        self._lock    = threading.Lock()
        self._timer:  Optional[threading.Timer] = None
        self._disk_buf = _DiskBuffer(
            cfg.get('disk_buffer_dir', '/tmp/sentinel'),
            cfg.get('disk_buffer_max_mb', 500),
        )

    def init(self) -> None:
        self._exec(f'CREATE DATABASE IF NOT EXISTS {self._db}')
        self._exec(f"""
            CREATE TABLE IF NOT EXISTS {self._db}.{self._table}
            (
                timestamp  String,
                record_id  String,
                trace_id   String,
                span_id    String,
                service    String,
                env        String,
                host       String,
                version    String,
                request_id String,
                tenant_id  String,
                layer      String,
                level      String,
                message    String,
                context    String
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(parseDateTimeBestEffort(timestamp))
            ORDER BY (timestamp, service, layer)
            TTL parseDateTimeBestEffort(timestamp) + INTERVAL 90 DAY
        """)
        self._schedule_flush()
        threading.Thread(target=self._drain_disk_buffer, daemon=True).start()

    def enqueue(self, record: LogRecord) -> None:
        if record.is_audit:
            self._append_audit(record)
        with self._lock:
            self._queue.append(record)
            if len(self._queue) >= self._batch:
                self._flush_locked()

    def _schedule_flush(self) -> None:
        self._timer = threading.Timer(2.0, self._flush_and_reschedule)
        self._timer.daemon = True
        self._timer.start()

    def _flush_and_reschedule(self) -> None:
        self.flush()
        self._schedule_flush()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._queue:
            return
        batch = self._queue[:]
        self._queue.clear()
        rows  = '\n'.join(json.dumps(r.to_dict()) for r in batch)
        query = f'INSERT INTO {self._db}.{self._table} FORMAT JSONEachRow'
        try:
            url  = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
            data = rows.encode('utf-8')
            req  = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-ndjson')
            if self._user:
                cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
                req.add_header('Authorization', f'Basic {cred}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status not in (200, 201):
                    if self._debug:
                        print(f'[SENTINEL] ClickHouse error: {resp.status}', file=sys.stderr)
                    self._disk_buf.write(batch)
        except Exception as exc:
            if self._debug:
                print(f'[SENTINEL] Flush error: {exc}', file=sys.stderr)
            self._disk_buf.write(batch)

    def _drain_disk_buffer(self) -> None:
        lines = self._disk_buf.drain()
        if not lines:
            return
        query = f'INSERT INTO {self._db}.{self._table} FORMAT JSONEachRow'
        try:
            url  = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
            data = '\n'.join(lines).encode('utf-8')
            req  = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-ndjson')
            if self._user:
                cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
                req.add_header('Authorization', f'Basic {cred}')
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass

    def _append_audit(self, record: LogRecord) -> None:
        try:
            os.makedirs(os.path.dirname(self._audit_path), exist_ok=True)
            with open(self._audit_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record.to_dict()) + '\n')
        except Exception:
            pass

    def _exec(self, query: str) -> None:
        url = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
        req = urllib.request.Request(url, method='POST')
        if self._user:
            cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
            req.add_header('Authorization', f'Basic {cred}')
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f'ClickHouse DDL failed: status={resp.status}')


# ── OTel OTLP/HTTP exporter ───────────────────────────────────────────────────

_SEVERITY_MAP = {
    LogLevel.DEBUG: 5, LogLevel.INFO: 9, LogLevel.WARN: 13,
    LogLevel.ERROR: 17, LogLevel.FATAL: 21,
}


class _OtlpExporter:
    def __init__(self, endpoint: str):
        self._endpoint = endpoint.rstrip('/') + '/v1/logs'
        self._queue:   List[LogRecord] = []
        self._lock     = threading.Lock()
        self._start_flush()

    def enqueue(self, record: LogRecord) -> None:
        with self._lock:
            self._queue.append(record)
            if len(self._queue) >= 50:
                threading.Thread(target=self._flush, daemon=True).start()

    def _start_flush(self) -> None:
        def loop():
            while True:
                time.sleep(2)
                self._flush()
        threading.Thread(target=loop, daemon=True).start()

    def _flush(self) -> None:
        with self._lock:
            if not self._queue:
                return
            batch = self._queue[:]
            self._queue.clear()

        if not batch:
            return

        first = batch[0]
        body  = {
            'resourceLogs': [{
                'resource': {
                    'attributes': _kv_list({
                        'service.name':    first.service,
                        'host.name':       first.host,
                        'service.version': first.version,
                    }),
                },
                'scopeLogs': [{
                    'scope': {'name': 'sentinel-sdk'},
                    'logRecords': [
                        {
                            'timeUnixNano':   str(int(
                                datetime.datetime.fromisoformat(r.timestamp)
                                .timestamp() * 1_000_000_000
                            )),
                            'severityNumber': _SEVERITY_MAP.get(r.level, 9),
                            'severityText':   r.level,
                            'traceId':        r.trace_id,
                            'spanId':         r.span_id,
                            'body':           {'stringValue': r.message},
                            'attributes':     _kv_list({
                                'layer':      r.layer,
                                'env':        r.env,
                                'request_id': r.request_id,
                                'tenant_id':  r.tenant_id,
                                **_flatten_ctx(r.context),
                            }),
                        }
                        for r in batch
                    ],
                }],
            }],
        }

        try:
            data = json.dumps(body).encode('utf-8')
            req  = urllib.request.Request(self._endpoint, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass


def _kv_list(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for k, v in obj.items():
        if v is None:
            continue
        if isinstance(v, bool):
            out.append({'key': k, 'value': {'boolValue': v}})
        elif isinstance(v, (int, float)):
            out.append({'key': k, 'value': {'doubleValue': float(v)}})
        else:
            out.append({'key': k, 'value': {'stringValue': str(v)}})
    return out


def _flatten_ctx(ctx: Any, prefix: str = '', depth: int = 0) -> Dict[str, Any]:
    if depth > 3 or not isinstance(ctx, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in ctx.items():
        key = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_ctx(v, key, depth + 1))
        else:
            out[key] = v
    return out


# ── SentinelMeta ─────────────────────────────────────────────────────────────

class SentinelMeta(type):
    _sentinel_agent: Optional['SentinelPython'] = None

    def __new__(mcs, name, bases, namespace, **kwargs):
        cls   = super().__new__(mcs, name, bases, namespace, **kwargs)
        layer = namespace.get('_sentinel_layer') or infer_layer(name)
        for attr, val in namespace.items():
            if attr.startswith('_'):
                continue
            if callable(val) and not isinstance(val, (classmethod, staticmethod, property)):
                setattr(cls, attr, mcs._wrap(val, name, attr, layer))
        return cls

    @staticmethod
    def _wrap(fn: Callable, cls_name: str, method: str, layer: str) -> Callable:
        is_async = inspect.iscoroutinefunction(fn)

        if is_async:
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                agent = SentinelMeta._sentinel_agent
                start = time.perf_counter()
                tid   = _get_trace_id()
                sid   = _get_session_id()
                if agent:
                    agent._emit(
                        f'{cls_name}.{method} called',
                        layer=layer, level=LogLevel.INFO,
                        trace_id=tid,
                        context={'className': cls_name, 'functionName': method,
                                 'isAsync': True, 'sessionId': sid},
                    )
                try:
                    result = await fn(*args, **kwargs)
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → ok ({ms:.1f}ms)',
                            layer=layer, level=LogLevel.INFO,
                            trace_id=tid,
                            context={'className': cls_name, 'functionName': method,
                                     'durationMs': ms, 'isAsync': True, 'sessionId': sid},
                        )
                    return result
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → error: {exc}',
                            layer=layer, level=LogLevel.ERROR,
                            trace_id=tid,
                            context={'className': cls_name, 'functionName': method,
                                     'durationMs': ms, 'isAsync': True, 'sessionId': sid,
                                     'exceptionType': type(exc).__name__,
                                     'stackTrace': traceback.format_exc()},
                        )
                    raise
            return async_wrapper
        else:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                agent = SentinelMeta._sentinel_agent
                start = time.perf_counter()
                tid   = _get_trace_id()
                sid   = _get_session_id()
                if agent:
                    agent._emit(
                        f'{cls_name}.{method} called',
                        layer=layer, level=LogLevel.INFO,
                        trace_id=tid,
                        context={'className': cls_name, 'functionName': method,
                                 'isAsync': False, 'sessionId': sid},
                    )
                try:
                    result = fn(*args, **kwargs)
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → ok ({ms:.1f}ms)',
                            layer=layer, level=LogLevel.INFO,
                            trace_id=tid,
                            context={'className': cls_name, 'functionName': method,
                                     'durationMs': ms, 'isAsync': False, 'sessionId': sid},
                        )
                    return result
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → error: {exc}',
                            layer=layer, level=LogLevel.ERROR,
                            trace_id=tid,
                            context={'className': cls_name, 'functionName': method,
                                     'durationMs': ms, 'isAsync': False, 'sessionId': sid,
                                     'exceptionType': type(exc).__name__,
                                     'stackTrace': traceback.format_exc()},
                        )
                    raise
            return wrapper


T = TypeVar('T')


# ── Health server ─────────────────────────────────────────────────────────────

class _HealthServer(threading.Thread):
    def __init__(self, port: int, service_name: str, process_start: float):
        super().__init__(daemon=True)
        self._port          = port
        self._service_name  = service_name
        self._process_start = process_start
        self._ready         = False

    def set_ready(self) -> None:
        self._ready = True

    def run(self) -> None:
        import http.server

        srv = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    body = json.dumps({
                        'status':      'ok',
                        'service':     srv._service_name,
                        'uptime':      round(time.time() - srv._process_start, 2),
                        'pid':         os.getpid(),
                        'activeUsers': _sessions.active_count(),
                    }).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/ready':
                    code = 200 if srv._ready else 503
                    body = json.dumps(
                        {'status': 'ready' if srv._ready else 'not_ready'}
                    ).encode()
                    self.send_response(code)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/sessions':
                    # Live active-session count endpoint
                    body = json.dumps({
                        'activeUsers':   _sessions.active_count(),
                        'activeSessions': _sessions.active_sessions(),
                    }).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        class _ThreadingHTTPServer(
            http.server.ThreadingHTTPServer
            if hasattr(http.server, 'ThreadingHTTPServer')
            else http.server.HTTPServer
        ):
            pass

        with _ThreadingHTTPServer(('0.0.0.0', self._port), Handler) as httpd:
            httpd.serve_forever()


# ── Helpers for session/traceId extraction from request headers ───────────────

def _extract_session_id(headers: Dict[str, str]) -> str:
    """
    Pull session ID from common header/cookie patterns.
    If nothing found, generate a new one. This new ID is also returned
    so callers can set it as a response cookie / header.
    """
    for key in ('x-session-id', 'x-session', 'session-id'):
        val = headers.get(key) or headers.get(key.title())
        if val:
            return val
    # Try cookie header
    cookie_hdr = headers.get('cookie', '') or headers.get('Cookie', '')
    for part in cookie_hdr.split(';'):
        k, _, v = part.strip().partition('=')
        if k.strip().lower() in ('sessionid', 'session_id', 'sid', 'sentinel_sid'):
            return v.strip()
    # Generate a new unique session id
    return f'sess_{secrets.token_hex(12)}'


def _extract_user_id(headers: Dict[str, str], path: str = '') -> Optional[str]:
    for key in ('x-user-id', 'x-userid', 'x-user', 'authorization'):
        val = headers.get(key) or headers.get(key.title())
        if val and key != 'authorization':
            return val
    return None


# ── Main agent ────────────────────────────────────────────────────────────────

class SentinelPython:
    def __init__(self, service_name: str = 'python-service', **cfg):
        self.service_name   = service_name
        self._process_start = time.time()
        self._net_bytes_in  = 0
        self._net_bytes_out = 0

        _disk_dir = cfg.get('disk_buffer_dir', os.path.join('/tmp', 'sentinel'))

        self._cfg = {
            'clickhouse_host':     cfg.get('clickhouse_host',     os.getenv('CLICKHOUSE_HOST',     'http://localhost:8123')),
            'clickhouse_database': cfg.get('clickhouse_database', os.getenv('CLICKHOUSE_DATABASE', 'sentinel')),
            'clickhouse_table':    cfg.get('clickhouse_table',    os.getenv('CLICKHOUSE_TABLE',    'logs')),
            'clickhouse_user':     cfg.get('clickhouse_user',     os.getenv('CLICKHOUSE_USER',     '')),
            'clickhouse_password': cfg.get('clickhouse_password', os.getenv('CLICKHOUSE_PASSWORD', '')),
            'batch_size':          cfg.get('batch_size',          50),
            'slow_query_ms':       cfg.get('slow_query_ms',       200),
            'slow_http_ms':        cfg.get('slow_http_ms',        1000),
            'slow_function_ms':    cfg.get('slow_function_ms',    500),
            'debug':               cfg.get('debug',               False),
            'sampling_rate':       cfg.get('sampling_rate',       1.0),
            'cert_check_hosts':    cfg.get('cert_check_hosts',    []),
            'cert_check_interval': cfg.get('cert_check_interval', 6 * 3600),
            'otlp_endpoint':       cfg.get('otlp_endpoint',       os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', '')),
            'health_port':         int(cfg.get('health_port',     os.getenv('SENTINEL_HEALTH_PORT', 9090))),
            'log_level':           (cfg.get('log_level') or os.getenv('LOG_LEVEL', LogLevel.DEBUG)).upper(),
            'disk_buffer_dir':     _disk_dir,
            'disk_buffer_max_mb':  cfg.get('disk_buffer_max_mb',  500),
            'audit_log_path':      cfg.get('audit_log_path',      os.path.join(_disk_dir, 'sentinel-audit.ndjson')),
            'enabled':             cfg.get('enabled',             os.getenv('SENTINEL_ENABLED', 'true').lower() != 'false'),
        }

        self._enabled   = self._cfg['enabled']
        self._min_level = self._cfg['log_level']
        self._writer    = _ClickHouseWriter(self._cfg)
        self._otlp      = _OtlpExporter(self._cfg['otlp_endpoint']) if self._cfg['otlp_endpoint'] else None
        self._health    = _HealthServer(self._cfg['health_port'], service_name, self._process_start)
        self._instrumented: set = set()
        self._trace_id  = _gen_16hex()  # process-level fallback trace id

        if HAS_PSUTIL:
            self._prev_cpu_times = _psutil.cpu_times()

    # ── Public API ────────────────────────────────────────────────────────────

    def hook(self) -> 'SentinelPython':
        if not self._enabled:
            return self
        self._writer.init()
        self._health.start()

        SentinelMeta._sentinel_agent = self

        self._patch_print()
        self._patch_logging()
        self._patch_requests()
        self._patch_httpx()
        self._patch_sqlalchemy()
        self._patch_psycopg2()
        self._patch_neo4j()
        self._patch_redis()
        self._patch_mongodb()
        self._patch_queues()
        self._hook_process()
        self._start_vitals()
        if self._cfg['cert_check_hosts']:
            self._start_cert_monitor()

        self._health.set_ready()

        self._emit(
            f'Sentinel Python Agent hooked on "{self.service_name}"',
            layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
            context={
                'python_version':       sys.version,
                'pid':                  os.getpid(),
                'processUptimeSeconds': 0,
                'cpuCoreCount':         os.cpu_count() or 1,
                'host':                 os.getenv('HOSTNAME', socket.gethostname()),
                'version':              os.getenv('SERVICE_VERSION', '0.0.0'),
            },
        )
        return self

    def disable(self) -> None:
        self._enabled = False

    def enable(self) -> None:
        self._enabled = True

    def set_log_level(self, level: str) -> None:
        self._min_level = level.upper()

    def active_users(self) -> int:
        """Return the current number of active unique sessions."""
        return _sessions.active_count()

    def instrument(self, target: Any, layer: Optional[str] = None) -> 'SentinelPython':
        cls    = target if isinstance(target, type) else type(target)
        cls_id = id(cls)
        if cls_id in self._instrumented:
            return self
        self._instrumented.add(cls_id)

        resolved_layer = layer or infer_layer(cls.__name__)
        methods = [
            name for name, val in inspect.getmembers(cls, predicate=inspect.isfunction)
            if not name.startswith('__')
        ]
        for method_name in methods:
            try:
                orig    = getattr(cls, method_name)
                wrapped = SentinelMeta._wrap(orig, cls.__name__, method_name, resolved_layer)
                setattr(cls, method_name, wrapped)
            except (AttributeError, TypeError):
                pass

        self._emit(
            f'Instrumented: {cls.__name__} ({len(methods)} methods → {resolved_layer})',
            layer=LogLayer.OBSERVABILITY, level=LogLevel.DEBUG,
        )
        return self

    def track(self, layer: str = LogLayer.BUSINESS_LOGIC, slow_ms: Optional[float] = None):
        def decorator(fn: Callable) -> Callable:
            threshold = slow_ms or self._cfg['slow_function_ms']
            is_async  = inspect.iscoroutinefunction(fn)

            if is_async:
                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    start = time.perf_counter()
                    tid   = _get_trace_id()
                    sid   = _get_session_id()
                    self._emit(f'{fn.__qualname__} called', layer=layer, level=LogLevel.INFO,
                               trace_id=tid,
                               context={'functionName': fn.__qualname__, 'isAsync': True, 'sessionId': sid})
                    try:
                        result = await fn(*args, **kwargs)
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → ok ({ms:.1f}ms){"[SLOW]" if ms > threshold else ""}',
                            layer=layer, level=LogLevel.WARN if ms > threshold else LogLevel.INFO,
                            trace_id=tid,
                            context={'functionName': fn.__qualname__, 'durationMs': ms,
                                     'isAsync': True, 'sessionId': sid})
                        return result
                    except Exception as exc:
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(f'{fn.__qualname__} → error: {exc}', layer=layer, level=LogLevel.ERROR,
                                   trace_id=tid,
                                   context={'functionName': fn.__qualname__, 'durationMs': ms,
                                            'isAsync': True, 'sessionId': sid,
                                            'exceptionType': type(exc).__name__,
                                            'stackTrace': traceback.format_exc()})
                        raise
                return async_wrapper
            else:
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    start = time.perf_counter()
                    tid   = _get_trace_id()
                    sid   = _get_session_id()
                    self._emit(f'{fn.__qualname__} called', layer=layer, level=LogLevel.INFO,
                               trace_id=tid,
                               context={'functionName': fn.__qualname__, 'isAsync': False, 'sessionId': sid})
                    try:
                        result = fn(*args, **kwargs)
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → ok ({ms:.1f}ms){"[SLOW]" if ms > threshold else ""}',
                            layer=layer, level=LogLevel.WARN if ms > threshold else LogLevel.INFO,
                            trace_id=tid,
                            context={'functionName': fn.__qualname__, 'durationMs': ms,
                                     'isAsync': False, 'sessionId': sid})
                        return result
                    except Exception as exc:
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(f'{fn.__qualname__} → error: {exc}', layer=layer, level=LogLevel.ERROR,
                                   trace_id=tid,
                                   context={'functionName': fn.__qualname__, 'durationMs': ms,
                                            'isAsync': False, 'sessionId': sid,
                                            'exceptionType': type(exc).__name__,
                                            'stackTrace': traceback.format_exc()})
                        raise
                return wrapper
        return decorator

    def log(self, message: str, layer: str = LogLayer.BUSINESS_LOGIC,
            level: str = LogLevel.INFO, context: Optional[Dict] = None) -> None:
        self._emit(message, layer=layer, level=level, context=context)

    def audit(self, message: str, context: Optional[Dict] = None) -> None:
        self._emit(message, layer=LogLayer.SECURITY, level=LogLevel.INFO,
                   context=context, is_audit=True)

    def flush(self) -> None:
        self._writer.flush()

    # ── Internal emitter ──────────────────────────────────────────────────────

    def _emit(
        self,
        message:    str,
        layer:      str = LogLayer.BUSINESS_LOGIC,
        level:      str = LogLevel.INFO,
        context:    Optional[Dict] = None,
        trace_id:   Optional[str] = None,
        is_audit:   bool = False,
    ) -> None:
        if not self._enabled:
            return

        if not is_audit and _LEVEL_ORDER.get(level, 0) < _LEVEL_ORDER.get(self._min_level, 0):
            return

        rate = self._cfg['sampling_rate']
        if not is_audit and rate < 1.0:
            if level in (LogLevel.INFO, LogLevel.DEBUG):
                import random
                if random.random() > rate:
                    return

        raw_ctx = dict(context or {})
        raw_ctx.setdefault('samplingRate',     rate)
        raw_ctx.setdefault('samplingDecision', 'sampled')

        # Inject thread-local session/user context if not already present
        raw_ctx.setdefault('sessionId', _get_session_id())
        raw_ctx.setdefault('userId',    _get_user_id())

        ctx = mask_context(raw_ctx)

        # Resolve trace_id: explicit > thread-local > process fallback
        effective_trace_id = trace_id or _get_trace_id()
        if effective_trace_id == 'untracked':
            effective_trace_id = self._trace_id

        record = LogRecord(
            message=message,
            layer=layer,
            level=level,
            service=self.service_name,
            context=ctx,
            trace_id=effective_trace_id,
            is_audit=is_audit,
        )
        if self._cfg['debug']:
            print(f'[SENTINEL] {record}', file=sys.stderr)

        self._writer.enqueue(record)
        if self._otlp:
            self._otlp.enqueue(record)

    # ── Common request enter/exit logic (shared by all middleware) ────────────

    def _request_enter(
        self,
        method:     str,
        path:       str,
        headers:    Dict[str, str],
        body_bytes: int = 0,
    ) -> Tuple[str, str, Optional[str], bool]:
        """
        Called at the start of every inbound request.
        Returns (trace_id, session_id, user_id, is_new_session).
        Also sets thread-local context so all downstream calls inherit.
        """
        tp = headers.get('traceparent') or headers.get('Traceparent')
        if tp:
            parsed = parse_traceparent(tp)
            trace_id = parsed['trace_id'] if parsed else _gen_16hex()
        else:
            trace_id = _gen_16hex()

        session_id = _extract_session_id(headers)
        user_id    = _extract_user_id(headers, path)
        is_new     = _sessions.touch(session_id, user_id)

        _set_request_ctx(trace_id, session_id, user_id)

        if is_new:
            self._emit(
                f'Session started: {session_id}',
                layer=LogLayer.OBSERVABILITY, level=LogLevel.INFO,
                trace_id=trace_id,
                context={
                    'sessionId':   session_id,
                    'userId':      user_id,
                    'sessionStart': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'activeUsers': _sessions.active_count(),
                    'clientIp':    headers.get('x-forwarded-for') or headers.get('x-real-ip'),
                    'userAgent':   headers.get('user-agent'),
                },
            )

        self._net_bytes_in += body_bytes
        return trace_id, session_id, user_id, is_new

    def _request_exit(
        self,
        method:      str,
        path:        str,
        status_code: int,
        trace_id:    str,
        session_id:  str,
        user_id:     Optional[str],
        start:       float,
        headers_in:  Dict[str, str],
        res_bytes:   int = 0,
    ) -> None:
        ms             = (time.perf_counter() - start) * 1000
        is_slow        = ms > self._cfg['slow_http_ms']
        rate_limit_hit = status_code == 429
        origin         = headers_in.get('origin', '')
        cors_violation = status_code == 403 and bool(origin)
        bot_signal     = bool(_BOT_UA_RE.search(headers_in.get('user-agent', '')))
        user_agent     = headers_in.get('user-agent', '')
        is_auth_path   = bool(_AUTH_PATH_RE.search(path))
        is_auth_fail   = status_code in (401, 403)

        _sessions.touch(session_id, user_id)

        self._net_bytes_out += res_bytes

        if is_auth_path or is_auth_fail:
            self._emit(
                f'Auth event: {method} {path} → {status_code}',
                layer=LogLayer.SECURITY,
                level=LogLevel.WARN if is_auth_fail else LogLevel.INFO,
                trace_id=trace_id,
                is_audit=True,
                context=mask_context({
                    'authResult':    'success' if status_code < 400 else 'failure',
                    'path':          path, 'statusCode': status_code,
                    'userAgent':     user_agent, 'sessionId': session_id,
                    'userId':        user_id,
                    'failureReason': f'HTTP {status_code}' if is_auth_fail else None,
                }),
            )

        self._emit(
            f'← {method} {path} {status_code} ({ms:.1f}ms)'
            f'{"[SLOW]" if is_slow else ""}{"[RATE-LIMITED]" if rate_limit_hit else ""}',
            layer=LogLayer.API_GATEWAY,
            level=LogLevel.ERROR if status_code >= 500
                  else LogLevel.WARN if status_code >= 400
                  else LogLevel.INFO,
            trace_id=trace_id,
            context=mask_context({
                'method': method, 'path': path,
                'statusCode': status_code, 'durationMs': ms,
                'rateLimitHit': rate_limit_hit,
                'responseSizeBytes': res_bytes or None,
                'corsViolation': cors_violation, 'botSignal': bot_signal,
                'sessionId': session_id, 'userId': user_id,
                'activeUsers': _sessions.active_count(),
            }),
        )
        _clear_request_ctx()

    # ── Flask middleware ──────────────────────────────────────────────────────

    def flask_middleware(self, app: Any) -> Any:
        sentinel = self

        @app.before_request
        def before():
            import flask
            req    = flask.request
            hdrs   = {k.lower(): v for k, v in req.headers.items()}
            body   = int(req.content_length or 0)
            trace_id, session_id, user_id, is_new = sentinel._request_enter(
                req.method, req.path, hdrs, body)
            flask.g._sentinel_start      = time.perf_counter()
            flask.g._sentinel_trace_id   = trace_id
            flask.g._sentinel_session_id = session_id
            flask.g._sentinel_user_id    = user_id

            sentinel._emit(
                f'→ {req.method} {req.path}',
                layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                trace_id=trace_id,
                context=mask_context({
                    'method': req.method, 'path': req.path,
                    'clientIp': req.remote_addr, 'userAgent': hdrs.get('user-agent'),
                    'userId': user_id, 'sessionId': session_id,
                    'requestSizeBytes': body,
                    'activeUsers': _sessions.active_count(),
                }),
            )

        @app.after_request
        def after(response):
            import flask
            req        = flask.request
            hdrs       = {k.lower(): v for k, v in req.headers.items()}
            trace_id   = getattr(flask.g, '_sentinel_trace_id',   sentinel._trace_id)
            session_id = getattr(flask.g, '_sentinel_session_id', 'unknown')
            user_id    = getattr(flask.g, '_sentinel_user_id',    None)
            start      = getattr(flask.g, '_sentinel_start',      time.perf_counter())
            res_bytes  = int(response.content_length or 0)

            response.headers['traceparent'] = build_traceparent(trace_id, _gen_8hex())
            response.headers['x-session-id'] = session_id

            sentinel._request_exit(
                req.method, req.path, response.status_code,
                trace_id, session_id, user_id, start, hdrs, res_bytes)
            return response

        return app

    # ── FastAPI / ASGI middleware ─────────────────────────────────────────────

    def fastapi_middleware(self, app: Any) -> Any:
        sentinel = self

        class _Middleware:
            def __init__(self, asgi_app):
                self.app = asgi_app

            async def __call__(self, scope, receive, send):
                if scope['type'] != 'http':
                    await self.app(scope, receive, send)
                    return

                start      = time.perf_counter()
                method     = scope.get('method', '')
                path       = scope.get('path', '')
                hdrs       = {k.decode().lower(): v.decode() for k, v in scope.get('headers', [])}
                body_size  = int(hdrs.get('content-length', 0))

                trace_id, session_id, user_id, is_new = sentinel._request_enter(
                    method, path, hdrs, body_size)

                sentinel._emit(
                    f'→ {method} {path}',
                    layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                    trace_id=trace_id,
                    context=mask_context({
                        'method': method, 'path': path,
                        'userAgent': hdrs.get('user-agent'), 'userId': user_id,
                        'sessionId': session_id,
                        'requestSizeBytes': body_size,
                        'activeUsers': _sessions.active_count(),
                    }),
                )

                status_code = [200]
                res_bytes   = [0]

                async def send_wrapper(message):
                    if message['type'] == 'http.response.start':
                        status_code[0] = message['status']
                        new_headers = list(message.get('headers', []))
                        new_headers.append((b'traceparent', build_traceparent(trace_id, _gen_8hex()).encode()))
                        new_headers.append((b'x-session-id', session_id.encode()))
                        message = dict(message)
                        message['headers'] = new_headers
                    elif message['type'] == 'http.response.body':
                        chunk = message.get('body', b'')
                        res_bytes[0] += len(chunk)
                    await send(message)

                await self.app(scope, receive, send_wrapper)

                sentinel._request_exit(
                    method, path, status_code[0],
                    trace_id, session_id, user_id, start, hdrs, res_bytes[0])

        app.add_middleware(_Middleware)
        return app

    # ── Django middleware ─────────────────────────────────────────────────────

    def django_middleware(self) -> type:
        """
        Returns a Django middleware class. Register in settings.py:

            MIDDLEWARE = [
                'myapp.sentinel_mw.SentinelDjangoMiddleware',
                ...
            ]

        Or use get_response pattern directly:

            sentinel = init_sentinel(...)
            SentinelDjangoMiddleware = sentinel.django_middleware()
        """
        sentinel = self

        class SentinelDjangoMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                hdrs = {k.lower().replace('http_', '').replace('_', '-'): v
                        for k, v in request.META.items()
                        if k.startswith('HTTP_') or k in ('CONTENT_TYPE', 'CONTENT_LENGTH')}
                # Django puts headers in META with HTTP_ prefix
                hdrs.setdefault('user-agent', request.META.get('HTTP_USER_AGENT', ''))
                hdrs.setdefault('traceparent', request.META.get('HTTP_TRACEPARENT', ''))
                hdrs.setdefault('x-session-id', request.META.get('HTTP_X_SESSION_ID', ''))
                hdrs.setdefault('x-user-id', request.META.get('HTTP_X_USER_ID', ''))
                hdrs.setdefault('cookie', request.META.get('HTTP_COOKIE', ''))

                body_bytes = int(request.META.get('CONTENT_LENGTH', 0) or 0)
                trace_id, session_id, user_id, is_new = sentinel._request_enter(
                    request.method, request.path, hdrs, body_bytes)

                start = time.perf_counter()
                sentinel._emit(
                    f'→ {request.method} {request.path}',
                    layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                    trace_id=trace_id,
                    context=mask_context({
                        'method': request.method, 'path': request.path,
                        'clientIp': request.META.get('REMOTE_ADDR'),
                        'userAgent': hdrs.get('user-agent'), 'userId': user_id,
                        'sessionId': session_id,
                        'requestSizeBytes': body_bytes,
                        'activeUsers': _sessions.active_count(),
                    }),
                )

                response = self.get_response(request)

                res_bytes = int(getattr(response, 'content', b'').__len__()
                               if hasattr(response, 'content') else 0)
                response['traceparent'] = build_traceparent(trace_id, _gen_8hex())
                response['x-session-id'] = session_id

                sentinel._request_exit(
                    request.method, request.path, response.status_code,
                    trace_id, session_id, user_id, start, hdrs, res_bytes)
                return response

        return SentinelDjangoMiddleware

    # ── print() patch ─────────────────────────────────────────────────────────

    def _patch_print(self) -> None:
        sentinel   = self
        orig_print = builtins.print

        def sentinel_print(*args, **kwargs):
            msg = ' '.join(str(a) for a in args)
            if '[SENTINEL]' in msg:
                orig_print(*args, **kwargs)
                return
            sentinel._emit(mask_pii(msg), layer=LogLayer.BUSINESS_LOGIC, level=LogLevel.INFO)
            orig_print(f'[SENTINEL] {msg}', **kwargs)

        builtins.print = sentinel_print

    # ── logging module patch ──────────────────────────────────────────────────

    def _patch_logging(self) -> None:
        sentinel = self
        _LEVEL_MAP = {
            logging.DEBUG:    LogLevel.DEBUG,
            logging.INFO:     LogLevel.INFO,
            logging.WARNING:  LogLevel.WARN,
            logging.ERROR:    LogLevel.ERROR,
            logging.CRITICAL: LogLevel.FATAL,
        }

        class SentinelHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                sentinel._emit(
                    mask_pii(record.getMessage()),
                    layer=LogLayer.OBSERVABILITY,
                    level=_LEVEL_MAP.get(record.levelno, LogLevel.INFO),
                    context={'logger': record.name, 'module': record.module, 'funcName': record.funcName},
                )

        logging.getLogger().addHandler(SentinelHandler())

    # ── requests patch ────────────────────────────────────────────────────────

    def _patch_requests(self) -> None:
        if not HAS_REQUESTS:
            return
        sentinel  = self
        orig_send = _requests.Session.send

        def patched_send(self_session, request, **kwargs):
            start = time.perf_counter()
            url   = str(request.url)
            body  = request.body or b''
            try:
                body_bytes = len(body) if isinstance(body, (bytes, str)) else 0
            except TypeError:
                body_bytes = 0
            sentinel._net_bytes_in += body_bytes

            span_id  = _gen_8hex()
            tid      = _get_trace_id()
            if tid == 'untracked':
                tid = sentinel._trace_id
            request.headers['traceparent'] = build_traceparent(tid, span_id)

            sentinel._emit(
                f'→ {request.method} {mask_pii(url)}',
                layer=LogLayer.SERVICE, level=LogLevel.INFO,
                trace_id=tid,
                context={'method': request.method, 'path': mask_pii(url),
                         'requestSizeBytes': body_bytes, 'sessionId': _get_session_id()},
            )
            try:
                response = orig_send(self_session, request, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sc = response.status_code
                res_bytes = len(response.content) if response.content else 0
                sentinel._net_bytes_out += res_bytes

                rate_limit_hit       = sc == 429
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', -1))
                retry_count          = int(request.headers.get('X-Retry-Count', 0))

                if _AUTH_PATH_RE.search(url) or sc in (401, 403):
                    sentinel._emit(
                        f'Auth event: {request.method} {mask_pii(url)} → {sc}',
                        layer=LogLayer.SECURITY,
                        level=LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                        trace_id=tid, is_audit=True,
                        context=mask_context({
                            'authResult':    'success' if sc < 400 else 'failure',
                            'path':          mask_pii(url), 'statusCode': sc,
                            'sessionId':     _get_session_id(),
                            'failureReason': f'HTTP {sc}' if sc >= 400 else None,
                        }),
                    )

                sentinel._emit(
                    f'← {request.method} {mask_pii(url)} {sc} ({ms:.1f}ms)'
                    f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.SERVICE,
                    level=(LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO),
                    trace_id=tid,
                    context=mask_context({
                        'method': request.method, 'path': mask_pii(url),
                        'statusCode': sc, 'durationMs': ms,
                        'responseSizeBytes': res_bytes or None,
                        'rateLimitHit': rate_limit_hit,
                        'rateLimitRemaining': rate_limit_remaining if rate_limit_remaining >= 0 else None,
                        'downstreamService': mask_pii(url), 'downstreamStatusCode': sc,
                        'downstreamDurationMs': ms, 'thirdPartyLatencyMs': ms,
                        'retryCount': retry_count or None,
                        'sessionId': _get_session_id(),
                    }),
                )
                return response
            except Exception as exc:
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'✗ {request.method} {mask_pii(url)} — {exc}',
                    layer=LogLayer.SERVICE, level=LogLevel.ERROR,
                    trace_id=tid,
                    context={'method': request.method, 'path': mask_pii(url), 'durationMs': ms,
                             'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc(),
                             'sessionId': _get_session_id()},
                )
                raise

        _requests.Session.send = patched_send

    # ── httpx patch ───────────────────────────────────────────────────────────

    def _patch_httpx(self) -> None:
        if not HAS_HTTPX:
            return
        sentinel  = self
        orig_send = _httpx.Client.send

        def patched_send(self_client, request, **kwargs):
            start   = time.perf_counter()
            url     = str(request.url)
            span_id = _gen_8hex()
            tid     = _get_trace_id()
            if tid == 'untracked':
                tid = sentinel._trace_id
            request.headers['traceparent'] = build_traceparent(tid, span_id)

            sentinel._emit(
                f'→ httpx {request.method} {mask_pii(url)}',
                layer=LogLayer.SERVICE, level=LogLevel.INFO,
                trace_id=tid,
                context={'method': request.method, 'path': mask_pii(url),
                         'sessionId': _get_session_id()},
            )
            try:
                response = orig_send(self_client, request, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sc = response.status_code
                rate_limit_hit = sc == 429
                sentinel._emit(
                    f'← httpx {request.method} {mask_pii(url)} {sc} ({ms:.1f}ms)'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.SERVICE,
                    level=LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                    trace_id=tid,
                    context=mask_context({
                        'method': request.method, 'path': mask_pii(url),
                        'statusCode': sc, 'durationMs': ms,
                        'rateLimitHit': rate_limit_hit,
                        'downstreamStatusCode': sc, 'thirdPartyLatencyMs': ms,
                        'sessionId': _get_session_id(),
                    }),
                )
                return response
            except Exception as exc:
                sentinel._emit(
                    f'✗ httpx {request.method} {mask_pii(url)} — {exc}',
                    layer=LogLayer.SERVICE, level=LogLevel.ERROR,
                    trace_id=tid,
                    context={'method': request.method, 'path': mask_pii(url),
                             'exceptionType': type(exc).__name__,
                             'stackTrace': traceback.format_exc(),
                             'sessionId': _get_session_id()},
                )
                raise

        _httpx.Client.send = patched_send

    # ── SQLAlchemy patch ──────────────────────────────────────────────────────

    def _patch_sqlalchemy(self) -> None:
        if not HAS_SQLALCHEMY:
            return
        sentinel  = self
        slow_ms   = self._cfg['slow_query_ms']
        _starts: Dict[int, Tuple[float, str]] = {}

        @_sa_event.listens_for(_sa.engine.Engine, 'before_cursor_execute')
        def before(conn, cursor, statement, parameters, context, executemany):
            _starts[id(cursor)] = (time.perf_counter(), _get_trace_id())

        @_sa_event.listens_for(_sa.engine.Engine, 'after_cursor_execute')
        def after(conn, cursor, statement, parameters, context, executemany):
            entry   = _starts.pop(id(cursor), (time.perf_counter(), sentinel._trace_id))
            start, tid = entry
            ms      = (time.perf_counter() - start) * 1000
            is_slow = ms > slow_ms
            stmt_up = statement.strip().upper()
            is_migration = bool(_MIGRATION_RE.match(stmt_up))
            is_commit    = stmt_up.startswith('COMMIT')
            is_rollback  = stmt_up.startswith('ROLLBACK')

            sentinel._emit(
                f'SQLAlchemy{"[SLOW]" if is_slow else ""}: {statement[:120]}',
                layer=LogLayer.DATA_ACCESS,
                level=LogLevel.WARN if is_slow else LogLevel.INFO,
                trace_id=tid,
                context={
                    'database': 'sqlalchemy',
                    'queryType': stmt_up.split()[0] if stmt_up else 'UNKNOWN',
                    'durationMs': ms, 'slowQuery': is_slow,
                    'slowQueryThresholdMs': slow_ms,
                    'migrationName':     statement[:80] if is_migration else None,
                    'migrationStatus':   'completed' if is_migration else None,
                    'transactionAction': 'commit' if is_commit else 'rollback' if is_rollback else None,
                    'sessionId': _get_session_id(),
                },
            )

    # ── psycopg2 patch ────────────────────────────────────────────────────────

    def _patch_psycopg2(self) -> None:
        if not HAS_PSYCOPG2:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']

        try:
            orig_execute = _psycopg2.extensions.cursor.execute

            def patched_execute(self_cursor, query, vars=None):
                start = time.perf_counter()
                tid   = _get_trace_id()
                try:
                    result  = orig_execute(self_cursor, query, vars)
                    ms      = (time.perf_counter() - start) * 1000
                    is_slow = ms > slow_ms
                    stmt_up = str(query).strip().upper()
                    is_migration = bool(_MIGRATION_RE.match(stmt_up))
                    is_commit    = stmt_up.startswith('COMMIT')
                    is_rollback  = stmt_up.startswith('ROLLBACK')

                    pool      = getattr(getattr(self_cursor, 'connection', None), '_pool', None)
                    pool_size = getattr(pool, 'maxconn', None)
                    pool_used = getattr(pool, '_used',   None)

                    sentinel._emit(
                        f'psycopg2{"[SLOW]" if is_slow else ""}: {str(query)[:120]}',
                        layer=LogLayer.DATA_ACCESS,
                        level=LogLevel.WARN if is_slow else LogLevel.INFO,
                        trace_id=tid,
                        context={
                            'database': 'postgres',
                            'queryType': stmt_up.split()[0] if stmt_up else 'UNKNOWN',
                            'durationMs': ms, 'rowsAffected': self_cursor.rowcount,
                            'slowQuery': is_slow, 'slowQueryThresholdMs': slow_ms,
                            'migrationName':     str(query)[:80] if is_migration else None,
                            'migrationStatus':   'completed'      if is_migration else None,
                            'transactionAction': 'commit' if is_commit else 'rollback' if is_rollback else None,
                            'connectionPoolSize': pool_size,
                            'connectionPoolUsed': len(pool_used) if pool_used is not None else None,
                            'sessionId': _get_session_id(),
                        },
                    )
                    return result
                except Exception as exc:
                    ms  = (time.perf_counter() - start) * 1000
                    msg = str(exc).lower()
                    sentinel._emit(
                        f'psycopg2 error: {exc}',
                        layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                        trace_id=tid,
                        context={
                            'database': 'postgres', 'durationMs': ms,
                            'deadlock': 'deadlock' in msg, 'lockTimeout': 'lock timeout' in msg,
                            'exceptionType': type(exc).__name__,
                            'stackTrace': traceback.format_exc(),
                            'sessionId': _get_session_id(),
                        },
                    )
                    raise

            _psycopg2.extensions.cursor.execute = patched_execute

        except (AttributeError, TypeError) as e:
            if self._cfg['debug']:
                print(f'[SENTINEL] psycopg2 cursor patch skipped: {e}', file=sys.stderr)

    # ── neo4j patch ───────────────────────────────────────────────────────────

    def _patch_neo4j(self) -> None:
        if not HAS_NEO4J:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']
        orig_run = _neo4j.Session.run

        def patched_run(self_session, query, parameters=None, **kwargs):
            start = time.perf_counter()
            tid   = _get_trace_id()
            try:
                result  = orig_run(self_session, query, parameters, **kwargs)
                ms      = (time.perf_counter() - start) * 1000
                is_slow = ms > slow_ms
                sentinel._emit(
                    f'Neo4j{"[SLOW]" if is_slow else ""}: {str(query)[:120]}',
                    layer=LogLayer.DATA_ACCESS,
                    level=LogLevel.WARN if is_slow else LogLevel.INFO,
                    trace_id=tid,
                    context={
                        'database': 'neo4j', 'durationMs': ms,
                        'slowQuery': is_slow, 'slowQueryThresholdMs': slow_ms,
                        'sessionId': _get_session_id(),
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Neo4j error: {exc}',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                    trace_id=tid,
                    context={
                        'database': 'neo4j',
                        'exceptionType': type(exc).__name__,
                        'stackTrace': traceback.format_exc(),
                        'sessionId': _get_session_id(),
                    },
                )
                raise

        _neo4j.Session.run = patched_run

    # ── redis patch ───────────────────────────────────────────────────────────

    def _patch_redis(self) -> None:
        if not HAS_REDIS:
            return
        sentinel = self
        _EVICTION_CMDS = {'DEL', 'UNLINK', 'EXPIRE', 'EXPIREAT', 'PEXPIRE', 'PEXPIREAT'}
        orig_execute_command = _redis.StrictRedis.execute_command

        def patched_execute_command(self_redis, *args, **kwargs):
            cmd   = str(args[0]).upper() if args else 'CMD'
            start = time.perf_counter()
            tid   = _get_trace_id()
            try:
                result = orig_execute_command(self_redis, *args, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'Redis {cmd} ({ms:.1f}ms)',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.DEBUG,
                    trace_id=tid,
                    context={
                        'database': 'redis', 'queryType': cmd, 'durationMs': ms,
                        'cacheHit': result is not None, 'cacheMiss': result is None,
                        'cacheEviction': cmd in _EVICTION_CMDS,
                        'sessionId': _get_session_id(),
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Redis {cmd} error: {exc}',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                    trace_id=tid,
                    context={'database': 'redis', 'queryType': cmd,
                             'exceptionType': type(exc).__name__,
                             'sessionId': _get_session_id()},
                )
                raise

        _redis.StrictRedis.execute_command = patched_execute_command

    # ── MongoDB / PyMongo patch ───────────────────────────────────────────────

    def _patch_mongodb(self) -> None:
        if not HAS_PYMONGO:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']

        try:
            from pymongo.collection import Collection

            _MONGO_OPS = [
                'find', 'find_one', 'insert_one', 'insert_many',
                'update_one', 'update_many', 'replace_one',
                'delete_one', 'delete_many', 'aggregate',
                'count_documents', 'estimated_document_count',
                'find_one_and_update', 'find_one_and_replace', 'find_one_and_delete',
                'bulk_write',
            ]

            for op_name in _MONGO_OPS:
                orig_op = getattr(Collection, op_name, None)
                if orig_op is None:
                    continue

                def make_wrapper(op, name):
                    @functools.wraps(op)
                    def wrapper(self_col, *args, **kwargs):
                        start = time.perf_counter()
                        tid   = _get_trace_id()
                        try:
                            result  = op(self_col, *args, **kwargs)
                            ms      = (time.perf_counter() - start) * 1000
                            is_slow = ms > slow_ms

                            # Determine row counts from result type
                            row_count = None
                            rows_affected = None
                            if hasattr(result, 'matched_count'):
                                rows_affected = result.matched_count
                            elif hasattr(result, 'inserted_count'):
                                rows_affected = result.inserted_count
                            elif hasattr(result, 'deleted_count'):
                                rows_affected = result.deleted_count

                            sentinel._emit(
                                f'MongoDB {name}{"[SLOW]" if is_slow else ""}: {self_col.full_name}',
                                layer=LogLayer.DATA_ACCESS,
                                level=LogLevel.WARN if is_slow else LogLevel.DEBUG,
                                trace_id=tid,
                                context={
                                    'database':             self_col.database.name,
                                    'collection':           self_col.name,
                                    'queryType':            name.upper(),
                                    'durationMs':           ms,
                                    'slowQuery':            is_slow,
                                    'slowQueryThresholdMs': slow_ms,
                                    'rowsAffected':         rows_affected,
                                    'sessionId':            _get_session_id(),
                                },
                            )
                            return result
                        except Exception as exc:
                            ms = (time.perf_counter() - start) * 1000
                            sentinel._emit(
                                f'MongoDB {name} error: {exc}',
                                layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                                trace_id=tid,
                                context={
                                    'database':      getattr(self_col, 'database', {}).name if hasattr(self_col, 'database') else 'mongodb',
                                    'collection':    self_col.name,
                                    'queryType':     name.upper(),
                                    'durationMs':    ms,
                                    'exceptionType': type(exc).__name__,
                                    'stackTrace':    traceback.format_exc(),
                                    'sessionId':     _get_session_id(),
                                },
                            )
                            raise
                    return wrapper

                setattr(Collection, op_name, make_wrapper(orig_op, op_name))

            sentinel._emit('pymongo patched', layer=LogLayer.OBSERVABILITY, level=LogLevel.DEBUG)
        except Exception as e:
            if self._cfg['debug']:
                print(f'[SENTINEL] pymongo patch failed: {e}', file=sys.stderr)

    # ── Queue instrumentation ─────────────────────────────────────────────────

    def _patch_queues(self) -> None:
        self._patch_celery()
        self._patch_pika()
        self._patch_aiokafka()

    def _patch_celery(self) -> None:
        if not HAS_CELERY:
            return
        sentinel = self

        @_celery_signals.task_prerun.connect
        def on_task_prerun(task_id, task, args, kwargs, **_):
            task._sentinel_start    = time.perf_counter()
            task._sentinel_trace_id = _get_trace_id()
            sentinel._emit(
                f'Celery task started: {task.name}',
                layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                trace_id=task._sentinel_trace_id,
                context={
                    'queueName': getattr(task, 'queue', 'default'),
                    'queueAction': 'consume', 'jobId': task_id, 'jobName': task.name,
                    'sessionId': _get_session_id(),
                },
            )

        @_celery_signals.task_postrun.connect
        def on_task_postrun(task_id, task, retval, state, **_):
            ms = (time.perf_counter() - getattr(task, '_sentinel_start', time.perf_counter())) * 1000
            tid = getattr(task, '_sentinel_trace_id', sentinel._trace_id)
            sentinel._emit(
                f'Celery task done: {task.name} [{state}] ({ms:.1f}ms)',
                layer=LogLayer.INFRASTRUCTURE,
                level=LogLevel.WARN if state == 'FAILURE' else LogLevel.INFO,
                trace_id=tid,
                context={
                    'queueName': getattr(task, 'queue', 'default'),
                    'queueAction': 'process', 'jobId': task_id,
                    'jobName': task.name, 'durationMs': ms, 'jobStatus': state,
                },
            )

        @_celery_signals.task_failure.connect
        def on_task_failure(task_id, exception, traceback_, **_):
            sentinel._emit(
                f'Celery task failed: {exception}',
                layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                context={
                    'jobId': task_id,
                    'exceptionType': type(exception).__name__,
                    'stackTrace': ''.join(traceback.format_tb(traceback_)),
                },
            )

    def _patch_pika(self) -> None:
        if not HAS_PIKA:
            return
        sentinel = self
        orig_pub = _pika.channel.Channel.basic_publish

        def patched_publish(self_ch, exchange, routing_key, body, properties=None, mandatory=False):
            headers = {}
            if properties and properties.headers:
                headers = dict(properties.headers)
            tid = _get_trace_id()
            if tid == 'untracked':
                tid = sentinel._trace_id
            headers['traceparent'] = build_traceparent(tid, _gen_8hex())
            if properties:
                properties.headers = headers
            else:
                properties = _pika.BasicProperties(headers=headers)

            start = time.perf_counter()
            try:
                result = orig_pub(self_ch, exchange, routing_key, body, properties, mandatory)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'RabbitMQ publish: {exchange or "(default)"}/{routing_key} ({ms:.1f}ms)',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                    trace_id=tid,
                    context={
                        'queueName': routing_key, 'queueAction': 'publish',
                        'exchange': exchange,
                        'messageBytes': len(body) if body else 0, 'durationMs': ms,
                        'sessionId': _get_session_id(),
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'RabbitMQ publish error: {exc}',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                    trace_id=tid,
                    context={
                        'queueName': routing_key, 'queueAction': 'publish',
                        'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc(),
                    },
                )
                raise

        _pika.channel.Channel.basic_publish = patched_publish

        orig_consume = _pika.channel.Channel.basic_consume

        def patched_consume(self_ch, queue, on_message_callback, **kwargs):
            def wrapped_callback(ch, method, properties, body):
                tp = (properties.headers or {}).get('traceparent') if properties else None
                trace_id = sentinel._trace_id
                if tp:
                    parsed = parse_traceparent(tp)
                    if parsed:
                        trace_id = parsed['trace_id']
                _request_ctx.trace_id = trace_id
                start = time.perf_counter()
                try:
                    on_message_callback(ch, method, properties, body)
                    ms = (time.perf_counter() - start) * 1000
                    sentinel._emit(
                        f'RabbitMQ consume: {queue} ({ms:.1f}ms)',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                        trace_id=trace_id,
                        context={'queueName': queue, 'queueAction': 'consume',
                                 'durationMs': ms, 'messageBytes': len(body) if body else 0},
                    )
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    sentinel._emit(
                        f'RabbitMQ consume error: {queue} — {exc}',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                        trace_id=trace_id,
                        context={'queueName': queue, 'queueAction': 'consume', 'durationMs': ms,
                                 'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc()},
                    )
                    raise

            return orig_consume(self_ch, queue, wrapped_callback, **kwargs)

        _pika.channel.Channel.basic_consume = patched_consume

    def _patch_aiokafka(self) -> None:
        if not HAS_AIOKAFKA:
            return
        sentinel  = self
        orig_send = _aiokafka.AIOKafkaProducer.send

        async def patched_send(self_producer, topic, value=None, key=None, headers=None, **kwargs):
            span_id   = _gen_8hex()
            tid       = _get_trace_id()
            if tid == 'untracked':
                tid = sentinel._trace_id
            tp_header = ('traceparent', build_traceparent(tid, span_id).encode())
            headers   = list(headers or []) + [tp_header]
            start     = time.perf_counter()
            try:
                result = await orig_send(self_producer, topic, value=value, key=key, headers=headers, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'Kafka produce: {topic} ({ms:.1f}ms)',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                    trace_id=tid,
                    context={'queueName': topic, 'queueAction': 'produce',
                             'messageBytes': len(value) if value else 0, 'durationMs': ms,
                             'sessionId': _get_session_id()},
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Kafka produce error: {topic} — {exc}',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                    trace_id=tid,
                    context={'queueName': topic, 'queueAction': 'produce',
                             'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc()},
                )
                raise

        _aiokafka.AIOKafkaProducer.send = patched_send

        orig_getone = _aiokafka.AIOKafkaConsumer.getone

        async def patched_getone(self_consumer, *partitions):
            msg      = await orig_getone(self_consumer, *partitions)
            tp       = None
            for k, v in (msg.headers or []):
                if k == 'traceparent':
                    tp = v.decode() if isinstance(v, bytes) else v
                    break
            trace_id = sentinel._trace_id
            if tp:
                parsed = parse_traceparent(tp)
                if parsed:
                    trace_id = parsed['trace_id']
            _request_ctx.trace_id = trace_id
            sentinel._emit(
                f'Kafka consume: {msg.topic}/{msg.partition} offset={msg.offset}',
                layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                trace_id=trace_id,
                context={'queueName': msg.topic, 'queueAction': 'consume',
                         'partition': msg.partition, 'offset': msg.offset,
                         'messageBytes': len(msg.value) if msg.value else 0},
            )
            return msg

        _aiokafka.AIOKafkaConsumer.getone = patched_getone

    # ── Process hooks ─────────────────────────────────────────────────────────

    def _hook_process(self) -> None:
        sentinel = self

        def handle_exception(exc_type, exc_value, exc_tb):
            sentinel._emit(
                f'Uncaught exception: {exc_value}',
                layer=LogLayer.SECURITY, level=LogLevel.FATAL,
                context={
                    'exceptionType':        exc_type.__name__,
                    'stackTrace':           ''.join(traceback.format_tb(exc_tb)),
                    'processUptimeSeconds': time.time() - sentinel._process_start,
                    'processExitCode':      1,
                },
            )
            sentinel._writer.flush()
            sys.__excepthook__(exc_type, exc_value, exc_tb)

        sys.excepthook = handle_exception

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                orig_handler = signal.getsignal(sig)

                def make_handler(s, oh):
                    def handler(signum, frame):
                        sentinel._emit(
                            f'Process signal: {s.name}',
                            layer=LogLayer.INFRASTRUCTURE, level=LogLevel.WARN,
                            context={
                                'containerEvent':       'stop',
                                'containerName':        sentinel.service_name,
                                'processUptimeSeconds': time.time() - sentinel._process_start,
                            },
                        )
                        sentinel._writer.flush()
                        if callable(oh):
                            oh(signum, frame)
                        else:
                            sys.exit(0)
                    return handler

                signal.signal(sig, make_handler(sig, orig_handler))
            except (ValueError, OSError):
                pass

    # ── Infrastructure vitals ─────────────────────────────────────────────────

    def _start_vitals(self) -> None:
        sentinel = self

        def vitals_loop():
            while True:
                time.sleep(30)
                try:
                    sentinel._emit_vitals()
                except Exception:
                    pass

        threading.Thread(target=vitals_loop, daemon=True).start()

        def disk_loop():
            while True:
                time.sleep(60)
                try:
                    sentinel._emit_disk_vitals()
                except Exception:
                    pass

        threading.Thread(target=disk_loop, daemon=True).start()

    def _emit_vitals(self) -> None:
        ctx: Dict[str, Any] = {
            'containerName':        self.service_name,
            'processUptimeSeconds': time.time() - self._process_start,
            'networkInBytes':       self._net_bytes_in,
            'networkOutBytes':      self._net_bytes_out,
            'host':                 os.getenv('HOSTNAME', socket.gethostname()),
            'activeUsers':          _sessions.active_count(),
        }

        if HAS_PSUTIL:
            # ── PSUTIL VITALS FIX ──────────────────────────────────────────
            # Always read fresh values directly from psutil on every vitals
            # emit. These are the exact fields requested:
            #   cpuPercent       = psutil.cpu_percent(interval=0.1)
            #   diskUsedPercent  = psutil.disk_usage('/').percent
            #   diskUsedBytes    = psutil.disk_usage('/').used
            #   memoryTotalBytes = psutil.virtual_memory().total
            # All other memory/cpu fields are also refreshed here.

            cpu_pct  = round(_psutil.cpu_percent(interval=0.1), 2)
            mem      = _psutil.virtual_memory()
            swap     = _psutil.swap_memory()
            disk     = _psutil.disk_usage('/')
            proc     = _psutil.Process(os.getpid())
            p_mem    = proc.memory_info()
            net_io   = _psutil.net_io_counters()

            ctx.update({
                # ── Requested fields (exact names) ──
                'cpuPercent':           cpu_pct,
                'diskUsedPercent':      round(disk.percent, 1),
                'diskUsedBytes':        disk.used,
                'memoryTotalBytes':     mem.total,
                # ── Additional useful fields ──
                'cpuCoreCount':         _psutil.cpu_count(logical=True) or os.cpu_count() or 1,
                'memoryUsedBytes':      p_mem.rss,
                'memoryAvailableBytes': mem.available,
                'swapUsedBytes':        swap.used,
                'diskTotalBytes':       disk.total,
            })

            level = LogLevel.WARN if cpu_pct > 85 else LogLevel.INFO
            msg   = (
                f'Process vitals: cpu={cpu_pct}% '
                f'disk={disk.percent:.1f}% '
                f'rss={p_mem.rss // 1024 // 1024}MB '
                f'mem_total={mem.total // 1024 // 1024}MB '
                f'activeUsers={_sessions.active_count()}'
            )
        else:
            try:
                import resource as _resource
                usage = _resource.getrusage(_resource.RUSAGE_SELF)
                ctx['memoryUsedBytes'] = usage.ru_maxrss * 1024
            except Exception:
                pass
            level = LogLevel.INFO
            msg   = f'Process vitals: uptime={ctx["processUptimeSeconds"]:.0f}s'

        self._emit(msg, layer=LogLayer.INFRASTRUCTURE, level=level, context=ctx)

    def _emit_disk_vitals(self) -> None:
        """
        Separate disk vitals — called every 60s.
        Also reads memoryTotalBytes and cpuPercent so the dashboard
        always has a recent reading even between vitals cycles.
        """
        if not HAS_PSUTIL:
            return
        try:
            disk     = _psutil.disk_usage('/')
            mem      = _psutil.virtual_memory()
            cpu_pct  = round(_psutil.cpu_percent(interval=0.1), 2)
            pct      = round(disk.percent, 1)
            self._emit(
                f'Disk vitals: {pct}% used ({disk.used // 1024 // 1024 // 1024}GB / {disk.total // 1024 // 1024 // 1024}GB)',
                layer=LogLayer.INFRASTRUCTURE,
                level=LogLevel.WARN if pct > 85 else LogLevel.INFO,
                context={
                    'diskUsedBytes':    disk.used,
                    'diskTotalBytes':   disk.total,
                    'diskUsedPercent':  pct,
                    'memoryTotalBytes': mem.total,
                    'cpuPercent':       cpu_pct,
                    'containerName':    self.service_name,
                    'activeUsers':      _sessions.active_count(),
                },
            )
        except Exception:
            pass

    # ── TLS certificate expiry monitor ────────────────────────────────────────

    def _start_cert_monitor(self) -> None:
        sentinel = self

        def check_all():
            for hostname in sentinel._cfg['cert_check_hosts']:
                try:
                    ctx_ssl = ssl.create_default_context()
                    conn    = ctx_ssl.wrap_socket(
                        socket.create_connection((hostname, 443), timeout=5),
                        server_hostname=hostname,
                    )
                    cert       = conn.getpeercert()
                    conn.close()

                    expiry_str = cert.get('notAfter', '')
                    expiry_dt  = datetime.datetime.strptime(
                        expiry_str, '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=datetime.timezone.utc)
                    days_left  = (expiry_dt - datetime.datetime.now(datetime.timezone.utc)).days

                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    issuer      = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'unknown'

                    level = (
                        LogLevel.FATAL if days_left < 7  else
                        LogLevel.ERROR if days_left < 14 else
                        LogLevel.WARN  if days_left < 30 else
                        LogLevel.INFO
                    )

                    sentinel._emit(
                        f'TLS cert: {hostname} expires in {days_left} days',
                        layer=LogLayer.INFRASTRUCTURE, level=level,
                        context={'certDomain': hostname, 'certExpiryDays': days_left, 'certIssuer': issuer},
                    )
                except Exception as exc:
                    sentinel._emit(
                        f'TLS cert check failed: {hostname} — {exc}',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                        context={'certDomain': hostname, 'exceptionType': type(exc).__name__},
                    )

        def monitor_loop():
            check_all()
            interval = sentinel._cfg['cert_check_interval']
            while True:
                time.sleep(interval)
                check_all()

        threading.Thread(target=monitor_loop, daemon=True).start()


# ── Zero-config auto-hook ─────────────────────────────────────────────────────
# Called automatically when SENTINEL_AUTO=1 env var is set.
# This is triggered by sentinel_autoload.py (sitecustomize companion).

_auto_agent: Optional[SentinelPython] = None


def _auto_hook() -> None:
    """
    Reads config entirely from environment variables and hooks the agent.
    No user code changes required — just set SENTINEL_AUTO=1.
    """
    global _auto_agent
    if _auto_agent is not None:
        return  # already hooked

    if os.getenv('SENTINEL_AUTO', '').lower() not in ('1', 'true', 'yes'):
        return

    service_name = os.getenv('SENTINEL_SERVICE_NAME', os.getenv('SERVICE_NAME', 'auto-service'))
    _auto_agent  = SentinelPython(
        service_name,
        clickhouse_host     = os.getenv('CLICKHOUSE_HOST',     'http://localhost:8123'),
        clickhouse_database = os.getenv('CLICKHOUSE_DATABASE', 'sentinel'),
        clickhouse_table    = os.getenv('CLICKHOUSE_TABLE',    'logs'),
        clickhouse_user     = os.getenv('CLICKHOUSE_USER',     ''),
        clickhouse_password = os.getenv('CLICKHOUSE_PASSWORD', ''),
        debug               = os.getenv('SENTINEL_DEBUG', '').lower() in ('1', 'true'),
        log_level           = os.getenv('LOG_LEVEL', 'INFO'),
        health_port         = int(os.getenv('SENTINEL_HEALTH_PORT', '9090')),
        otlp_endpoint       = os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', ''),
        sampling_rate       = float(os.getenv('SENTINEL_SAMPLING_RATE', '1.0')),
        disk_buffer_dir     = os.getenv('SENTINEL_DISK_BUFFER_DIR', '/tmp/sentinel'),
    )
    _auto_agent.hook()


# ── Factory ───────────────────────────────────────────────────────────────────

def init_sentinel(service_name: str = 'python-service', **kwargs) -> SentinelPython:
    """
    Standard one-liner init::

        sentinel = init_sentinel("my-service", debug=True)

    For ZERO-CONFIG operation (no init_sentinel call needed at all), set:

        SENTINEL_AUTO=1
        SENTINEL_SERVICE_NAME=my-service
        CLICKHOUSE_HOST=http://ch:8123

    and add to your Python startup:

        PYTHONPATH=/path/to/sdk python -c "import sentinel_autoload" myapp.py

    Or use the sitecustomize.py companion (see autoload/sentinel_autoload.py).
    """
    agent = SentinelPython(service_name, **kwargs)
    agent.hook()
    return agent

