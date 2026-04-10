#!/usr/bin/env python3
"""Embedded Telegram sidecar for single-container deployments.

This exposes the same small HTTP surface the proxy expects for Telegram
credentials, but authenticates from the per-request JSON credential payload
passed in X-OAuth-Credential-Data. That makes it usable inside an enclave,
where we cannot run a second Docker container for Telethon.
"""

import asyncio
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.types import Channel, Chat, User


BIND_HOST = os.environ.get("TELEGRAM_SIDECAR_HOST", "127.0.0.1")
PORT = int(os.environ.get("TELEGRAM_SIDECAR_PORT", "8082"))

loop = None
clients = {}


def entity_to_dict(entity):
    if isinstance(entity, User):
        return {
            "type": "user",
            "id": entity.id,
            "username": entity.username,
            "first_name": entity.first_name,
            "last_name": entity.last_name,
            "phone": entity.phone,
        }
    if isinstance(entity, (Chat, Channel)):
        return {
            "type": "channel" if isinstance(entity, Channel) else "chat",
            "id": entity.id,
            "title": entity.title,
            "username": getattr(entity, "username", None),
        }
    return {"type": "unknown", "id": getattr(entity, "id", None)}


def message_to_dict(msg):
    return {
        "id": msg.id,
        "date": msg.date.isoformat() if msg.date else None,
        "text": msg.text,
        "sender_id": msg.sender_id,
        "reply_to_msg_id": msg.reply_to.reply_to_msg_id if msg.reply_to else None,
        "out": msg.out,
    }


def run_async(coro):
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=30)


def parse_credential_data(headers):
    raw = headers.get("X-OAuth-Credential-Data")
    if not raw:
        raise ValueError("Missing X-OAuth-Credential-Data header")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid Telegram credential JSON: {exc}") from exc

    try:
        api_id = int(payload["api_id"])
        api_hash = str(payload["api_hash"])
        session_string = str(payload["session_string"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "Telegram credential must include api_id, api_hash, and session_string"
        ) from exc

    cred_name = headers.get("X-OAuth-Credential", "telegram")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    cache_key = f"{cred_name}:{digest}"
    return cache_key, api_id, api_hash, session_string


async def get_client(headers):
    cache_key, api_id, api_hash, session_string = parse_credential_data(headers)

    client = clients.get(cache_key)
    if client is None:
        client = TelegramClient(StringSession(session_string), api_id, api_hash)
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise RuntimeError("Telegram session string is not authorized")
        clients[cache_key] = client
        return client

    if not client.is_connected():
        await client.connect()

    return client


async def async_get_me(headers):
    client = await get_client(headers)
    me = await client.get_me()
    return entity_to_dict(me)


async def async_get_messages(headers, chat, limit=20):
    client = await get_client(headers)
    entity = await client.get_entity(chat)
    messages = await client.get_messages(entity, limit=limit)
    return {
        "chat": entity_to_dict(entity),
        "messages": [message_to_dict(m) for m in messages],
    }


async def async_get_dialogs(headers, limit=20):
    client = await get_client(headers)
    dialogs = await client.get_dialogs(limit=limit)
    return [
        {
            "name": d.name,
            "entity": entity_to_dict(d.entity),
            "unread_count": d.unread_count,
            "last_message": message_to_dict(d.message) if d.message else None,
        }
        for d in dialogs
    ]


async def async_send_message(headers, chat, message, reply_to=None):
    client = await get_client(headers)
    entity = await client.get_entity(chat)
    msg = await client.send_message(entity, message, reply_to=reply_to)
    return message_to_dict(msg)


class TelegramHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/health":
            self.json_response(
                200,
                {
                    "status": "ok",
                    "service": "telegram-sidecar",
                    "mode": "embedded",
                    "cached_clients": len(clients),
                },
            )
            return

        try:
            if path == "/messages":
                chat = params.get("chat", [None])[0]
                limit = int(params.get("limit", ["20"])[0])
                if not chat:
                    self.json_response(400, {"error": "Missing ?chat= parameter"})
                    return
                result = run_async(async_get_messages(self.headers, chat, limit))
                self.json_response(200, result)
                return

            if path == "/dialogs":
                limit = int(params.get("limit", ["20"])[0])
                result = run_async(async_get_dialogs(self.headers, limit))
                self.json_response(200, result)
                return

            if path == "/me":
                result = run_async(async_get_me(self.headers))
                self.json_response(200, result)
                return

            self.json_response(404, {"error": f"Unknown endpoint: {path}"})
        except ValueError as exc:
            self.json_response(400, {"error": str(exc)})
        except Exception as exc:
            self.json_response(500, {"error": str(exc)})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = (
            json.loads(self.rfile.read(content_length).decode("utf-8"))
            if content_length > 0
            else {}
        )

        path = urlparse(self.path).path

        try:
            if path == "/send":
                chat = body.get("chat")
                message = body.get("message")
                if not chat or not message:
                    self.json_response(400, {"error": "Missing 'chat' or 'message' in body"})
                    return
                result = run_async(async_send_message(self.headers, chat, message))
                self.json_response(200, result)
                return

            if path == "/reply":
                chat = body.get("chat")
                message = body.get("message")
                reply_to = body.get("reply_to")
                if not chat or not message or reply_to is None:
                    self.json_response(
                        400,
                        {"error": "Missing 'chat', 'message', or 'reply_to' in body"},
                    )
                    return
                result = run_async(
                    async_send_message(
                        self.headers, chat, message, reply_to=int(reply_to)
                    )
                )
                self.json_response(200, result)
                return

            self.json_response(404, {"error": f"Unknown endpoint: {path}"})
        except ValueError as exc:
            self.json_response(400, {"error": str(exc)})
        except Exception as exc:
            self.json_response(500, {"error": str(exc)})

    def json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[telegram-sidecar] {args[0]} {args[1]} {args[2]}\n")


def run_loop():
    global loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_forever()


def main():
    thread = Thread(target=run_loop, daemon=True)
    thread.start()

    server = HTTPServer((BIND_HOST, PORT), TelegramHandler)
    print(
        f"[telegram-sidecar] Listening on {BIND_HOST}:{PORT} (embedded mode)",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
