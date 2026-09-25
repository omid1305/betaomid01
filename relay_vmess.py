# relay_vmess.py
# ══════════════════════════════════════════════════════════════════════════
# VMess AEAD Relay — سازگار با Xray-core 24/25/26
#
#   ✔ KDF chain مطابق دقیق Xray-core (HMAC chain با salt "VMess AEAD KDF")
#   ✔ AuthID = KDF16(uuid_bytes, nil, timeBytes)  ← دو path element!
#   ✔ cmdKey = MD5(uuid_bytes + "c48619fe-8f02-3309-bc9d-5f32e4617ffd")
#   ✔ salt strings عیناً مطابق Xray
#   ✔ Response header با AEAD envelope (68 bytes)
#   ✔ throttle + check_and_use مشترک با VLESS
# ══════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import hmac
import secrets
import struct
import time
import logging
import socket
from uuid import UUID

from fastapi import WebSocket, WebSocketDisconnect
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import main
from relay_vless import check_and_use
from speed_limit import throttle

logger = logging.getLogger("OMIDIRAN_PANEL.VMESS")

RELAY_BUF = 256 * 1024
TCP_CONNECT_TIMEOUT = 10.0
FIRST_FRAME_TIMEOUT = 15.0

# ══════════════════════════════════════════════════════════════════════════
# Salt strings — عیناً مطابق Xray-core (به فاصله‌ها و آندرلاین‌ها دقت کن)
# ══════════════════════════════════════════════════════════════════════════
KDF_SALT = b"VMess AEAD KDF"

SALT_REQ_LEN_KEY = b"VMess Header AEAD Key_Length"
SALT_REQ_LEN_IV  = b"VMess Header AEAD IV_Length"
SALT_REQ_PAY_KEY = b"VMess Header AEAD Key"
SALT_REQ_PAY_IV  = b"VMess Header AEAD IV"

SALT_RESP_LEN_KEY = b"AEAD Resp Header Len Key"
SALT_RESP_LEN_IV  = b"AEAD Resp Header Len IV"
SALT_RESP_PAY_KEY = b"AEAD Resp Header Key"
SALT_RESP_PAY_IV  = b"AEAD Resp Header IV"

# ثابت مشهور Xray برای cmdKey
CMD_KEY_SUFFIX = b"c48619fe-8f02-3309-bc9d-5f32e4617ffd"

# sec_type values
SEC_NONE = 5
SEC_ZERO = 6


# ══════════════════════════════════════════════════════════════════════════
# KDF — مطابق دقیق Xray-core
# ══════════════════════════════════════════════════════════════════════════
def _kdf(key: bytes, *paths: bytes) -> bytes:
    """Xray-core KDF chain:
        h = HMAC-SHA256(key, "VMess AEAD KDF")
        for each p in paths: h = HMAC-SHA256(h, p)
        return h  (32 bytes)
    """
    h = hmac.new(key, KDF_SALT, hashlib.sha256).digest()
    for p in paths:
        h = hmac.new(h, p, hashlib.sha256).digest()
    return h


def _kdf16(key: bytes, *paths: bytes) -> bytes:
    return _kdf(key, *paths)[:16]


# ══════════════════════════════════════════════════════════════════════════
# Decode request header
# ══════════════════════════════════════════════════════════════════════════
def _decode_request_header(data: bytes, user_uuid: str):
    """Parse VMess AEAD request header.
    Returns: (info dict | None, error message | None)
    """
    try:
        u_bytes = UUID(user_uuid).bytes
    except ValueError:
        return None, "فرمت UUID نامعتبر است"

    if len(data) < 34:  # 16 (authID) + 2 (enc len) + 16 (tag)
        return None, "داده‌ی هدر کافی نیست"

    auth_id = data[:16]

    # ══════════════════════════════════════════════════════════════════
    # AuthID validation — کلید موفقیت همین‌جاست
    #   Xray: AuthID = KDF16(uuid_bytes, nil, timeBytes)
    #   → دو path element: nil (خالی) + 8-byte big-endian timestamp
    # ══════════════════════════════════════════════════════════════════
    now = int(time.time())
    valid = False
    for delta in range(-120, 121):
        t = now + delta
        t_bytes = struct.pack(">Q", t)
        expected = _kdf16(u_bytes, b"", t_bytes)   # ← b"" حیاتی است
        if hmac.compare_digest(expected, auth_id):
            valid = True
            break

    if not valid:
        return None, "اعتبارسنجی Auth ID ناموفق بود"

    # ── cmdKey = MD5(uuid_bytes + suffix) ──
    cmd_key = hashlib.md5(u_bytes + CMD_KEY_SUFFIX).digest()

    # ── Length AEAD key/IV ──
    len_key = _kdf16(cmd_key, auth_id, SALT_REQ_LEN_KEY)
    len_iv  = _kdf(cmd_key, auth_id, SALT_REQ_LEN_IV)[:12]

    try:
        dec_len = AESGCM(len_key).decrypt(len_iv, data[16:34], None)
        header_len = struct.unpack(">H", dec_len)[0]
    except Exception as e:
        return None, f"خطا در رمزگشایی طول هدر: {e}"

    if len(data) < 34 + header_len + 16:
        return None, "بدنه‌ی هدر ناقص است"

    # ── Payload AEAD key/IV ──
    payload_ct = data[34 : 34 + header_len + 16]
    header_end = 34 + header_len + 16

    pay_key = _kdf16(cmd_key, auth_id, SALT_REQ_PAY_KEY)
    pay_iv  = _kdf(cmd_key, auth_id, SALT_REQ_PAY_IV)[:12]

    try:
        payload = AESGCM(pay_key).decrypt(pay_iv, payload_ct, None)
    except Exception as e:
        return None, f"خطا در رمزگشایی بدنه‌ی هدر: {e}"

    if len(payload) < 41:
        return None, "ساختار هدر معتبر نیست"

    ver = payload[0]
    req_iv = payload[1:17]
    req_key = payload[17:33]
    res_check = payload[33]
    opt = payload[34]
    sec_byte = payload[35]
    sec_type = sec_byte & 0x0F
    # payload[36] = reserved
    cmd = payload[37]
    port = struct.unpack(">H", payload[38:40])[0]
    addr_type = payload[40]

    idx = 41
    if addr_type == 1:  # IPv4
        host = socket.inet_ntoa(payload[idx:idx+4])
        idx += 4
    elif addr_type == 2:  # Domain
        dlen = payload[idx]
        idx += 1
        host = payload[idx:idx+dlen].decode("utf-8", errors="ignore")
        idx += dlen
    elif addr_type == 3:  # IPv6
        host = socket.inet_ntop(socket.AF_INET6, payload[idx:idx+16])
        idx += 16
    else:
        return None, f"نوع آدرس ناشناخته: {addr_type}"

    return {
        "cmd_key": cmd_key,
        "auth_id": auth_id,
        "ver": ver,
        "req_iv": req_iv,
        "req_key": req_key,
        "res_check": res_check,
        "opt": opt,
        "sec_type": sec_type,
        "cmd": cmd,
        "host": host,
        "port": port,
        "body_init": data[header_end:],
    }, None


# ══════════════════════════════════════════════════════════════════════════
# Build AEAD-encrypted response header
# ══════════════════════════════════════════════════════════════════════════
def _build_response_header(info: dict) -> bytes:
    """Response header با AEAD envelope — دقیقاً مطابق Xray-core.

    Plaintext (34 bytes):
        [res_check (1)] [option (1)] [resp_iv (16)] [resp_key (16)]

    Wire format (68 bytes):
        [encrypted_length (18)] [encrypted_payload (50)]
        = 2+16                + 34+16
    """
    cmd_key = info["cmd_key"]
    auth_id = info["auth_id"]
    res_check = info["res_check"]

    # Fresh IV/key برای body encryption (در sec_type=NONE استفاده نمی‌شه،
    # ولی Xray انتظار داره که توی header باشن)
    resp_iv  = secrets.token_bytes(16)
    resp_key = secrets.token_bytes(16)

    plaintext = bytes([res_check, 0x00]) + resp_iv + resp_key

    # Response AEAD keys
    resp_len_key = _kdf16(cmd_key, auth_id, SALT_RESP_LEN_KEY)
    resp_len_iv  = _kdf(cmd_key, auth_id, SALT_RESP_LEN_IV)[:12]
    resp_pay_key = _kdf16(cmd_key, auth_id, SALT_RESP_PAY_KEY)
    resp_pay_iv  = _kdf(cmd_key, auth_id, SALT_RESP_PAY_IV)[:12]

    length_bytes = struct.pack(">H", len(plaintext))
    enc_len = AESGCM(resp_len_key).encrypt(resp_len_iv, length_bytes, None)
    enc_pay = AESGCM(resp_pay_key).encrypt(resp_pay_iv, plaintext, None)

    return enc_len + enc_pay


# ══════════════════════════════════════════════════════════════════════════
# Socket tuning
# ══════════════════════════════════════════════════════════════════════════
def _tune_socket(writer: asyncio.StreamWriter):
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════════════
# Data transfer: WS → TCP (uplink)
# ══════════════════════════════════════════════════════════════════════════
async def _vmess_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            main.stats["total_requests"] += 1
            if conn_id in main.connections:
                main.connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
# Data transfer: TCP → WS (downlink)
# ══════════════════════════════════════════════════════════════════════════
async def _vmess_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            if conn_id in main.connections:
                main.connections[conn_id]["bytes"] += len(data)
            await ws.send_bytes(data)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
# Main VMess tunnel
# ══════════════════════════════════════════════════════════════════════════
async def websocket_tunnel_vmess(websocket: WebSocket, uuid: str):
    await websocket.accept()
    conn_id = f"vmess-{id(websocket)}"
    ip = main.client_ip(websocket)

    async with main.LINKS_LOCK:
        real_uid, link = main.find_link_by_key(uuid)

    if not link or not main.is_link_allowed(link):
        logger.warning(f"🚫 VMess rejected uuid={uuid[:8]}… (not allowed)")
        await websocket.close(code=4000, reason="لینک غیرفعال یا منقضی شده است")
        return

    if not main.is_ip_allowed(link, real_uid, ip):
        logger.warning(f"🚫 VMess rejected uuid={uuid[:8]}… ip={ip} (ip limit)")
        await websocket.close(code=4001, reason="محدودیت تعداد آی‌پِی هم‌زمان")
        return

    main.connections[conn_id] = {
        "uuid": real_uid,
        "ip": ip,
        "bytes": 0,
        "connected_at": main.now_ir().isoformat(),
        "transport": "vmess-ws",
    }
    logger.info(f"✅ VMess [{conn_id}] uuid={real_uid[:8]}… ip={ip} total={len(main.connections)}")

    target_writer = None
    try:
        # ── Frame 1: AEAD header ──
        try:
            first_frame = await asyncio.wait_for(
                websocket.receive_bytes(), timeout=FIRST_FRAME_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.warning(f"⏱️  VMess first-frame timeout [{ip}]")
            return

        if not first_frame:
            return

        header_info, err = _decode_request_header(first_frame, real_uid)
        if err or not header_info:
            logger.warning(f"⚠️  VMess header parse error [{ip}]: {err}")
            await websocket.close(code=4002, reason="خطا در خواندن هدر VMess")
            return

        # ── Quota: header bytes ──
        if not await check_and_use(real_uid, len(first_frame)):
            await websocket.close(code=1008, reason="quota/disabled/unknown")
            return
        main.stats["total_requests"] += 1
        if conn_id in main.connections:
            main.connections[conn_id]["bytes"] += len(first_frame)

        # ── Check body encryption type (فقط NONE/ZERO پشتیبانی می‌شه) ──
        if header_info["sec_type"] not in (SEC_NONE, SEC_ZERO):
            logger.warning(
                f"⚠️  VMess unsupported sec_type={header_info['sec_type']} "
                f"[{conn_id}] — body will be relayed as-is"
            )

        host = header_info["host"]
        port = header_info["port"]

        # ── Connect to target ──
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TCP_CONNECT_TIMEOUT
            )
            target_writer = writer
            _tune_socket(writer)
        except Exception as e:
            logger.error(f"VMess connect failed {host}:{port} -> {e}")
            await websocket.close(code=4003, reason="امکان اتصال به مقصد نیست")
            return

        logger.info(
            f"➡️  VMess [{conn_id}] → {host}:{port} "
            f"sec_type={header_info['sec_type']} opt={header_info['opt']}"
        )

        # ── Send trailing data from first frame to target ──
        if header_info["body_init"]:
            writer.write(header_info["body_init"])
            await writer.drain()

        # ── Send AEAD-encrypted response header ──
        resp_header = _build_response_header(header_info)
        await websocket.send_bytes(resp_header)

        # ── Bidirectional relay ──
        done, pending = await asyncio.wait(
            {
                asyncio.create_task(_vmess_ws_to_tcp(websocket, writer, conn_id, real_uid)),
                asyncio.create_task(_vmess_tcp_to_ws(websocket, reader, conn_id, real_uid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(main.save_state())

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        main.stats["total_errors"] += 1
        main.error_logs.append({
            "error": str(exc),
            "type": "vmess_ws_tunnel",
            "time": main.now_ir().isoformat(),
        })
        logger.error(f"VMess tunnel error [{conn_id}]: {exc}")
    finally:
        main.connections.pop(conn_id, None)
        if target_writer:
            try:
                target_writer.close()
                await target_writer.wait_closed()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass
        logger.info(f"🔌 VMess closed [{conn_id}] total={len(main.connections)}")
