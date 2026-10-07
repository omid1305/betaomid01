# relay_vless.py
# VLESS over WebSocket relay — بازنویسی پایدار و دقیق (VLESS version 0x00)
#
# اهداف این نسخه:
#   • parser مقاوم در برابر headerهای fragmented / ناقص
#   • حذف خطاهای مبهم مثل unknown addr type=0 در packet ناقص
#   • full-duplex TCP <-> WebSocket relay با shutdown کنترل‌شده
#   • TCP keepalive + TCP_NODELAY روی socket مقصد
#   • تشخیص دقیق WS disconnect / TCP EOF / TCP reset / relay error
#   • محدود کردن اندازه header اولیه برای جلوگیری از مصرف حافظه غیرضروری
#   • حفظ API و ساختارهای state فعلی پنل

import asyncio
import secrets
import socket
import time
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    now_ir,
)
from speed_limit import throttle

# ══════════════════════════════════════════════════════════════════════════════
# Tuning
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = 256 * 1024
VLESS_VERSION = 0x00
INITIAL_HEADER_TIMEOUT = 15.0
MAX_INITIAL_BUFFER = 64 * 1024
TCP_CONNECT_TIMEOUT = 10.0

# TCP keepalive is deliberately conservative: it is not an application timeout
# and therefore cannot create a 30-second disconnect by itself.
TCP_KEEPIDLE = 60
TCP_KEEPINTVL = 20
TCP_KEEPCNT = 3


# ══════════════════════════════════════════════════════════════════════════════
# Small helpers
# ══════════════════════════════════════════════════════════════════════════════

class VLESSNeedMoreData(Exception):
    """Raised when the WebSocket frame does not yet contain a full VLESS header."""


class VLESSProtocolError(ValueError):
    """Raised when the received bytes are not a valid VLESS TCP request."""


class WSInitialDisconnect(Exception):
    """Raised when the client closes before a complete VLESS request arrives."""

    def __init__(self, code=None, reason=None):
        self.code = code
        self.reason = reason
        super().__init__(f"WebSocket disconnected code={code} reason={reason or '-'}")


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()

    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    return ws.client.host if ws.client else "نامشخص"


def _close_reason(meta: dict, reason: str) -> None:
    if reason and reason not in meta["close_reasons"]:
        meta["close_reasons"].append(reason)


def _append_error(error_text: str, conn_id: str, target: str | None) -> None:
    error_logs.append(
        {
            "error": error_text,
            "time": datetime.now().isoformat(),
            "conn_id": conn_id,
            "target": target,
        }
    )


def _is_peer_network_close(exc: BaseException) -> bool:
    """Known network-side close/reset errors that are not relay logic crashes."""
    return isinstance(
        exc,
        (
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            asyncio.IncompleteReadError,
        ),
    )


def _configure_tcp_socket(writer: asyncio.StreamWriter) -> None:
    """Best-effort TCP socket tuning; never let tuning break a live session."""
    try:
        sock = writer.transport.get_extra_info("socket")
    except Exception:
        sock = None

    if sock is None:
        return

    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError as exc:
        logger.debug("TCP_NODELAY unavailable: %s", exc)

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError as exc:
        logger.debug("SO_KEEPALIVE unavailable: %s", exc)
        return

    # Linux exposes these TCP keepalive knobs. Guard each one for portability.
    for option_name, value in (
        ("TCP_KEEPIDLE", TCP_KEEPIDLE),
        ("TCP_KEEPINTVL", TCP_KEEPINTVL),
        ("TCP_KEEPCNT", TCP_KEEPCNT),
    ):
        option = getattr(socket, option_name, None)
        if option is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError as exc:
            logger.debug("%s unavailable: %s", option_name, exc)


def _extract_ws_bytes(message: dict) -> bytes | None:
    """Return binary payload; text frames are accepted for compatibility."""
    msg_type = message.get("type")
    if msg_type == "websocket.disconnect":
        raise WSInitialDisconnect(message.get("code"), message.get("reason"))

    if msg_type != "websocket.receive":
        return b""

    raw = message.get("bytes")
    if raw is not None:
        return raw

    text = message.get("text")
    if text is not None:
        return text.encode()

    return b""


# ══════════════════════════════════════════════════════════════════════════════
# VLESS header parsing
# ══════════════════════════════════════════════════════════════════════════════

async def parse_vless_header(chunk: bytes):
    """Parse a VLESS request header.

    This function is intentionally strict about malformed bytes but explicitly
    distinguishes an incomplete header from an invalid header. That distinction
    lets the WebSocket relay accumulate fragmented first frames instead of
    incorrectly reporting errors such as `unknown addr type: 0`.
    """
    if not chunk:
        raise VLESSNeedMoreData

    # VLESS currently uses protocol version 0x00.
    # This is the wire-format used by Xray/V2Ray VLESS implementations.
    if chunk[0] != VLESS_VERSION:
        raise VLESSProtocolError(f"unsupported VLESS version: {chunk[0]}")

    # version(1) + UUID(16)
    pos = 17
    if len(chunk) < pos + 1:
        raise VLESSNeedMoreData

    addon_len = chunk[pos]
    pos += 1

    # addon bytes + command(1) + port(2) + address type(1)
    required = addon_len + 1 + 2 + 1
    if len(chunk) < pos + required:
        raise VLESSNeedMoreData

    pos += addon_len
    command = chunk[pos]
    pos += 1

    # Keep command parsing protocol-compatible here. The WebSocket endpoint
    # below explicitly limits this relay to TCP, while XHTTP reuses this parser
    # for both TCP/UDP-capable VLESS sessions.

    port = int.from_bytes(chunk[pos : pos + 2], "big")
    pos += 2
    if not 1 <= port <= 65535:
        raise VLESSProtocolError(f"invalid port: {port}")

    addr_type = chunk[pos]
    pos += 1

    if addr_type == 1:  # IPv4
        if len(chunk) < pos + 4:
            raise VLESSNeedMoreData
        address = ".".join(str(b) for b in chunk[pos : pos + 4])
        pos += 4

    elif addr_type == 2:  # Domain
        if len(chunk) < pos + 1:
            raise VLESSNeedMoreData
        domain_len = chunk[pos]
        pos += 1
        if domain_len == 0:
            raise VLESSProtocolError("empty domain in VLESS request")
        if len(chunk) < pos + domain_len:
            raise VLESSNeedMoreData
        address = chunk[pos : pos + domain_len].decode("utf-8", errors="strict")
        pos += domain_len

    elif addr_type == 3:  # IPv6
        if len(chunk) < pos + 16:
            raise VLESSNeedMoreData
        raw = chunk[pos : pos + 16]
        address = ":".join(
            f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2)
        )
        pos += 16

    else:
        raise VLESSProtocolError(f"unknown addr type: {addr_type}")

    return command, address, port, chunk[pos:]


async def _read_initial_vless_request(ws: WebSocket) -> tuple[bytes, int, str, int, bytes] | None:
    """Read enough WebSocket frames to obtain one complete VLESS request."""
    buffer = bytearray()

    while True:
        message = await ws.receive()
        chunk = _extract_ws_bytes(message)

        if chunk is None:
            continue
        if chunk:
            buffer.extend(chunk)

        if len(buffer) > MAX_INITIAL_BUFFER:
            raise VLESSProtocolError(
                f"initial VLESS request exceeds {MAX_INITIAL_BUFFER} bytes"
            )

        if not buffer:
            continue

        try:
            command, address, port, payload = await parse_vless_header(bytes(buffer))
            return bytes(buffer), command, address, port, payload
        except VLESSNeedMoreData:
            # First frame can legitimately be incomplete; keep receiving.
            continue


# ══════════════════════════════════════════════════════════════════════════════
# Quota/accounting
# ══════════════════════════════════════════════════════════════════════════════

async def check_and_use(uid: str, n: int) -> bool:
    """Atomically check link state and account traffic."""
    if n <= 0:
        return True

    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None or not is_link_allowed(link):
            return False

        link["used_bytes"] += n
        stats["total_bytes"] += n

        hour_key = now_ir().strftime("%H:00")
        hourly_traffic[hour_key] = hourly_traffic.get(hour_key, 0) + n
        return True


# ══════════════════════════════════════════════════════════════════════════════
# Full-duplex relay workers
# ══════════════════════════════════════════════════════════════════════════════

async def relay_ws_to_tcp(
    ws: WebSocket,
    writer: asyncio.StreamWriter,
    conn_id: str,
    uid: str,
    meta: dict,
) -> str:
    try:
        while True:
            message = await ws.receive()
            msg_type = message.get("type")

            if msg_type == "websocket.disconnect":
                code = message.get("code")
                reason = message.get("reason")
                close_reason = (
                    f"ws_disconnect(code={code}"
                    + (f", reason={reason}" if reason else "")
                    + ")"
                )
                _close_reason(meta, close_reason)
                logger.info(
                    f"📴 WS recv disconnect [{conn_id}] "
                    f"code={code} reason={reason or '-'}"
                )
                return close_reason

            if msg_type != "websocket.receive":
                continue

            data = message.get("bytes")
            if data is None:
                text = message.get("text")
                data = text.encode() if text is not None else b""

            if not data:
                continue

            if not await check_and_use(uid, len(data)):
                close_reason = "quota_or_disabled"
                _close_reason(meta, close_reason)
                try:
                    await ws.close(code=1008, reason="quota/disabled/unknown")
                except Exception:
                    pass
                logger.warning(f"🚫 WS quota/disabled [{conn_id}]")
                return close_reason

            await throttle(uid, len(data))
            stats["total_requests"] += 1
            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)

            meta["bytes_up"] += len(data)
            writer.write(data)

            transport = writer.transport
            if transport and transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()

    except WebSocketDisconnect as exc:
        code = getattr(exc, "code", None)
        reason = getattr(exc, "reason", None)
        close_reason = (
            f"ws_disconnect_exception(code={code}"
            + (f", reason={reason}" if reason else "")
            + ")"
        )
        _close_reason(meta, close_reason)
        logger.info(
            f"📴 WS disconnect exception [{conn_id}] "
            f"code={code} reason={reason or '-'}"
        )
        return close_reason

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        close_reason = f"ws_to_tcp_error({type(exc).__name__}: {exc})"
        _close_reason(meta, close_reason)
        stats["total_errors"] += 1
        _append_error(close_reason, conn_id, meta.get("target"))
        logger.exception(
            f"💥 WS→TCP error [{conn_id}] target={meta.get('target')}"
        )
        return close_reason

    finally:
        # If the client half-closes the WS side, half-close the outbound TCP
        # direction when supported. The final owner still closes the socket.
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(
    ws: WebSocket,
    reader: asyncio.StreamReader,
    conn_id: str,
    uid: str,
    meta: dict,
) -> str:
    first = True

    try:
        while True:
            data = await reader.read(RELAY_BUF)

            if not data:
                close_reason = "tcp_eof"
                _close_reason(meta, close_reason)
                logger.info(
                    f"📭 TCP EOF [{conn_id}] target={meta.get('target')} "
                    f"up={meta.get('bytes_up', 0)} down={meta.get('bytes_down', 0)}"
                )
                return close_reason

            if not await check_and_use(uid, len(data)):
                close_reason = "quota_or_disabled"
                _close_reason(meta, close_reason)
                try:
                    await ws.close(code=1008, reason="quota/disabled/unknown")
                except Exception:
                    pass
                logger.warning(f"🚫 TCP→WS quota/disabled [{conn_id}]")
                return close_reason

            await throttle(uid, len(data))
            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)

            meta["bytes_down"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        close_reason = f"tcp_to_ws_error({type(exc).__name__}: {exc})"
        _close_reason(meta, close_reason)

        # A TCP reset/abort is a peer-side network close rather than a Python
        # application crash. Keep it visible, but do not flood error counters.
        if _is_peer_network_close(exc):
            logger.info(
                f"🔄 TCP peer reset [{conn_id}] target={meta.get('target')} "
                f"error={type(exc).__name__}: {exc}"
            )
            return close_reason

        stats["total_errors"] += 1
        _append_error(close_reason, conn_id, meta.get("target"))
        logger.exception(
            f"💥 TCP→WS error [{conn_id}] target={meta.get('target')}"
        )
        return close_reason


# ══════════════════════════════════════════════════════════════════════════════
# WebSocket endpoint
# ══════════════════════════════════════════════════════════════════════════════

async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (not allowed)")
        try:
            await ws.close(code=1008, reason="not authorized")
        except Exception:
            pass
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning(
            f"🚫 WS rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)"
        )
        log_activity(
            "connection",
            f"اتصال {ip} به کانفیگ «{link.get('label','?')}» رد شد (محدودیت تعداد آی‌پی)",
            "warn",
        )
        try:
            await ws.close(code=1008, reason="ip limit reached")
        except Exception:
            pass
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }

    logger.info(
        f"✅ WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}"
    )
    log_activity(
        "connection",
        f"اتصال جدید از {ip} (کانفیگ {link.get('label','?')})",
        "info",
    )

    meta = {
        "started_monotonic": time.monotonic(),
        "target": None,
        "bytes_up": 0,
        "bytes_down": 0,
        "close_reasons": [],
    }

    writer: asyncio.StreamWriter | None = None

    try:
        try:
            initial_chunk, command, address, port, payload = await asyncio.wait_for(
                _read_initial_vless_request(ws),
                timeout=INITIAL_HEADER_TIMEOUT,
            )
        except WSInitialDisconnect as exc:
            close_reason = (
                f"ws_disconnect(code={exc.code}"
                + (f", reason={exc.reason}" if exc.reason else "")
                + ")"
            )
            _close_reason(meta, close_reason)
            logger.info(
                f"📴 Initial WS disconnect [{conn_id}] "
                f"code={exc.code} reason={exc.reason or '-'}"
            )
            return

        if not await check_and_use(uuid, len(initial_chunk)):
            _close_reason(meta, "quota_or_disabled")
            try:
                await ws.close(code=1008, reason="quota/disabled")
            except Exception:
                pass
            return

        stats["total_requests"] += 1
        if conn_id in connections:
            connections[conn_id]["bytes"] += len(initial_chunk)

        if command != 1:
            raise VLESSProtocolError(
                f"unsupported VLESS command for WebSocket TCP relay: {command}"
            )

        meta["bytes_up"] += len(initial_chunk)
        meta["target"] = f"{address}:{port}"

        logger.info(
            f"➡️  [{conn_id}] → {address}:{port} initial={len(initial_chunk)}B"
        )

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=TCP_CONNECT_TIMEOUT,
        )
        _configure_tcp_socket(writer)

        # The VLESS header itself is consumed by the relay. Only the remainder
        # (payload) is forwarded to the destination TCP stream.
        if payload:
            await throttle(uuid, len(payload))
            writer.write(payload)
            await writer.drain()

        ws_to_tcp_task = asyncio.create_task(
            relay_ws_to_tcp(ws, writer, conn_id, uuid, meta),
            name=f"vless-ws-to-tcp-{conn_id}",
        )
        tcp_to_ws_task = asyncio.create_task(
            relay_tcp_to_ws(ws, reader, conn_id, uuid, meta),
            name=f"vless-tcp-to-ws-{conn_id}",
        )

        # One side ending means the tunnel itself is finished: a single VLESS
        # WS maps to one TCP stream, so there is no valid second stream to keep
        # alive after either direction has terminated.
        done, pending = await asyncio.wait(
            {ws_to_tcp_task, tcp_to_ws_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        done_results: list[str] = []
        for task in done:
            try:
                result = task.result()
            except asyncio.CancelledError:
                result = "task_cancelled"
            except Exception as exc:
                result = f"task_exception({type(exc).__name__}: {exc})"
            if result:
                done_results.append(str(result))

        for task in pending:
            task.cancel()

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        for reason in done_results:
            _close_reason(meta, reason)

        # Persistence is already autosaved by main.py. Keep one asynchronous
        # save here so an active config's latest traffic is flushed promptly.
        asyncio.create_task(save_state())

    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        close_reason = "outer_timeout"
        _close_reason(meta, close_reason)
        _append_error("connection timeout", conn_id, meta.get("target"))
        logger.error(
            f"⏱️ WS timeout [{conn_id}] target={meta.get('target')}"
        )

    except WebSocketDisconnect as exc:
        close_reason = (
            f"outer_ws_disconnect(code={getattr(exc, 'code', None)}"
            + (
                f", reason={getattr(exc, 'reason', None)}"
                if getattr(exc, "reason", None)
                else ""
            )
            + ")"
        )
        _close_reason(meta, close_reason)
        logger.info(
            f"📴 Outer WS disconnect [{conn_id}] "
            f"code={getattr(exc, 'code', None)} "
            f"reason={getattr(exc, 'reason', None) or '-'}"
        )

    except VLESSNeedMoreData:
        # _read_initial_vless_request should absorb fragmentation itself. This
        # guard is kept only as a last-resort diagnostic.
        stats["total_errors"] += 1
        close_reason = "initial_header_incomplete"
        _close_reason(meta, close_reason)
        _append_error(close_reason, conn_id, None)
        logger.error(f"💥 Initial VLESS header incomplete [{conn_id}]")

    except VLESSProtocolError as exc:
        stats["total_errors"] += 1
        close_reason = f"vless_protocol_error({exc})"
        _close_reason(meta, close_reason)
        _append_error(close_reason, conn_id, meta.get("target"))
        logger.warning(
            f"⚠️ VLESS protocol error [{conn_id}] {exc}"
        )
        try:
            await ws.close(code=1002, reason="invalid vless request")
        except Exception:
            pass

    except asyncio.CancelledError:
        _close_reason(meta, "outer_task_cancelled")
        raise

    except Exception as exc:
        stats["total_errors"] += 1
        close_reason = f"outer_error({type(exc).__name__}: {exc})"
        _close_reason(meta, close_reason)
        _append_error(str(exc), conn_id, meta.get("target"))
        logger.exception(
            f"💥 WS outer error [{conn_id}] target={meta.get('target')}"
        )

    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        duration = time.monotonic() - meta["started_monotonic"]
        target = meta.get("target") or "unknown"
        reason_text = " | ".join(dict.fromkeys(meta["close_reasons"])) or "unknown"

        logger.info(
            f"🔌 WS closed [{conn_id}] "
            f"duration={duration:.3f}s "
            f"target={target} "
            f"up={meta['bytes_up']}B "
            f"down={meta['bytes_down']}B "
            f"reason={reason_text} "
            f"total={max(0, len(connections) - 1)}"
        )

        connections.pop(conn_id, None)
