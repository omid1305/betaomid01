# relay_vmess.py
# ══════════════════════════════════════════════════════════════════════════
# VMess AEAD Relay — هم‌راستا با relay_vless
#   • throttle() روی هر دو جهت (اعمال speed_limit_bytes)
#   • check_and_use() مشترک با VLESS → used_bytes + stats + hourly_traffic
#   • بدون LINKS_LOCK توی لوپ (بهینه برای throughput)
#   • بررسی is_link_allowed هر چانک (قطع خودکار در کوتا/غیرفعالی)
#   • TCP_NODELAY + RELAY_BUF=256KB (هم‌اندازه با VLESS)
#   • timeout روی فریم اول (15s) و اتصال TCP (10s)
# ══════════════════════════════════════════════════════════════════════════

import asyncio
import struct
import hashlib
import hmac
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

RELAY_BUF = 256 * 1024            # 256 KB — هم‌اندازه با VLESS
TCP_CONNECT_TIMEOUT = 10.0
FIRST_FRAME_TIMEOUT = 15.0


# ══════════════════════════════════════════════════════════════════════════
# KDF استاندارد VMess AEAD
# ══════════════════════════════════════════════════════════════════════════
def _kdf(key: bytes, path: list[bytes]) -> bytes:
    h = hmac.new(b"VMess AEAD KDF", key, hashlib.sha256).digest()
    for p in path:
        h = hmac.new(h, p, hashlib.sha256).digest()
    return h


def _decrypt_vmess_aead_header(data: bytes, user_uuid: str):
    """رمزگشایی هدر اولیه VMess AEAD و استخراج آدرس/پورت مقصد.
    Returns: (header_info | None, error_message | None)"""
    try:
        u_bytes = UUID(user_uuid).bytes
    except ValueError:
        return None, "فرمت UUID نامعتبر است"

    cmd_key = hashlib.md5(u_bytes + b"c48619fe-8f02-3309-bc9d-5f32e4617ffd").digest()

    if len(data) < 34:  # 16 (AuthID) + 2 (Encrypted Len) + 16 (Tag)
        return None, "داده‌ی هدر کافی نیست"

    auth_id = data[:16]

    # ── اعتبارسنجی Auth ID با پنجره‌ی زمانی ±120s ──
    now = int(time.time())
    match_time = None
    for t in range(now - 120, now + 121):
        t_bytes = struct.pack(">Q", t)
        expected_auth_id = hmac.new(cmd_key, t_bytes, hashlib.sha256).digest()[:16]
        if expected_auth_id == auth_id:
            match_time = t
            break

    if match_time is None:
        return None, "اعتبارسنجی Auth ID ناموفق بود (ناهمخوانی زمان یا UUID)"

    # ── رمزگشایی طول هدر (18 بایت) ──
    len_key = _kdf(cmd_key, [b"VMessAEADHeaderLengthKey", auth_id])[:16]
    len_iv = _kdf(cmd_key, [b"VMessAEADHeaderLengthIV", auth_id])[:12]

    try:
        # cryptography: ciphertext || tag را یکجا می‌گیره
        aesgcm_len = AESGCM(len_key)
        dec_len_bytes = aesgcm_len.decrypt(len_iv, data[16:18] + data[18:34], None)
        header_len = struct.unpack(">H", dec_len_bytes)[0]
    except Exception as e:
        return None, f"خطا در رمزگشایی طول هدر: {e}"

    offset = 34
    if len(data) < offset + header_len + 16:
        return None, "بدنه‌ی هدر ناقص است"

    # ── رمزگشایی بدنه‌ی هدر ──
    payload_enc = data[offset : offset + header_len]
    payload_tag = data[offset + header_len : offset + header_len + 16]
    header_end_offset = offset + header_len + 16

    payload_key = _kdf(cmd_key, [b"VMessAEADHeaderPayloadKey", auth_id])[:16]
    payload_iv = _kdf(cmd_key, [b"VMessAEADHeaderPayloadIV", auth_id])[:12]

    try:
        # cryptography: ciphertext || tag را یکجا می‌گیره
        aesgcm_payload = AESGCM(payload_key)
        payload = aesgcm_payload.decrypt(payload_iv, payload_enc + payload_tag, None)
    except Exception as e:
        return None, f"خطا در رمزگشایی بدنه‌ی هدر: {e}"

    if len(payload) < 41:
        return None, "ساختار هدر پاسخ معتبر نیست"

    ver = payload[0]
    req_iv = payload[1:17]
    req_key = payload[17:33]
    res_header_check = payload[33]
    opt = payload[34]
    p_sec = payload[35]
    sec_type = p_sec & 0x0F
    cmd = payload[37]
    port = struct.unpack(">H", payload[38:40])[0]
    addr_type = payload[40]

    idx = 41
    if addr_type == 1:  # IPv4
        host = socket.inet_ntoa(payload[idx : idx + 4])
        idx += 4
    elif addr_type == 2:  # Domain
        domain_len = payload[idx]
        idx += 1
        host = payload[idx : idx + domain_len].decode("utf-8", errors="ignore")
        idx += domain_len
    elif addr_type == 3:  # IPv6
        host = socket.inet_ntop(socket.AF_INET6, payload[idx : idx + 16])
        idx += 16
    else:
        return None, f"نوع آدرس ناشناخته: {addr_type}"

    remaining_data = data[header_end_offset:]

    return {
        "ver": ver,
        "req_iv": req_iv,
        "req_key": req_key,
        "res_header_check": res_header_check,
        "opt": opt,
        "sec_type": sec_type,
        "cmd": cmd,
        "host": host,
        "port": port,
        "remaining_data": remaining_data,
    }, None


def _tune_socket(writer: asyncio.StreamWriter):
    """TCP_NODELAY برای کاهش تاخیر (هم‌راستا با VLESS)."""
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════════════
# انتقال داده: WS → TCP (آپلینک کلاینت)
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
# انتقال داده: TCP → WS (دانلینک مقصد)
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
# تونل اصلی VMess
# ══════════════════════════════════════════════════════════════════════════
async def websocket_tunnel_vmess(websocket: WebSocket, uuid: str):
    """مدیریت تونل WebSocket برای پروتکل VMess — هم‌راستا با VLESS."""
    await websocket.accept()
    conn_id = f"vmess-{id(websocket)}"
    ip = main.client_ip(websocket)

    # ── resolve uuid (پشتیبانی از sub_token) ──
    async with main.LINKS_LOCK:
        real_uid, link = main.find_link_by_key(uuid)

    if not link or not main.is_link_allowed(link):
        logger.warning(f"🚫 VMess rejected uuid={uuid[:8]}… (not allowed)")
        await websocket.close(code=4000, reason="لینک غیرفعال یا منقضی شده است")
        return

    if not main.is_ip_allowed(link, real_uid, ip):
        logger.warning(f"🚫 VMess rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
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
        # ── فریم اول: هدر AEAD ──
        try:
            first_frame = await asyncio.wait_for(
                websocket.receive_bytes(), timeout=FIRST_FRAME_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.warning(f"⏱️  VMess first-frame timeout [{ip}]")
            return

        if not first_frame:
            return

        header_info, err = _decrypt_vmess_aead_header(first_frame, real_uid)
        if err or not header_info:
            logger.warning(f"VMess header parse error [{ip}]: {err}")
            await websocket.close(code=4002, reason="خطا در خواندن هدر VMess")
            return

        # ── ثبت مصرف فریم اول (هدر) از طریق مسیر مشترک ──
        if not await check_and_use(real_uid, len(first_frame)):
            await websocket.close(code=1008, reason="quota/disabled/unknown")
            return
        main.stats["total_requests"] += 1
        if conn_id in main.connections:
            main.connections[conn_id]["bytes"] += len(first_frame)

        host = header_info["host"]
        port = header_info["port"]

        # ── اتصال به مقصد ──
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TCP_CONNECT_TIMEOUT
            )
            target_writer = writer
            _tune_socket(writer)
        except Exception as e:
            logger.error(f"VMess connect failed {host}:{port} -> {e}")
            await websocket.close(code=4003, reason="امکان اتصال به مقصد وجود ندارد")
            return

        logger.info(f"➡️  VMess [{conn_id}] → {host}:{port}")

        # ── ارسال داده‌های باقی‌مانده از فریم اول به مقصد ──
        if header_info["remaining_data"]:
            writer.write(header_info["remaining_data"])
            await writer.drain()

        # ── بازگرداندن پاسخ هدر VMess به کلاینت ──
        res_header = bytes([header_info["res_header_check"], 0x00, 0x00, 0x00])
        await websocket.send_bytes(res_header)

        # ── انتقال دوطرفه تا بسته شدن یکی از جهات ──
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