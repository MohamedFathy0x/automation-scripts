#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prints your Telegram chat ID. Needs the bot token in config.json."""
import json, os, sys, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "config.json"), encoding="utf-8") as f:
    cfg = json.load(f)
token = cfg.get("telegram_bot_token") or os.environ.get("TELEGRAM_BOT_TOKEN")
if not token:
    sys.exit("Put your bot token in config.json first (telegram_bot_token).")

with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getUpdates", timeout=20) as r:
    data = json.load(r)

if not data.get("result"):
    sys.exit("No messages found. Open Telegram, send /start to your bot, then run this again.")

seen = set()
for upd in data["result"]:
    msg = upd.get("message") or upd.get("channel_post") or {}
    chat = msg.get("chat") or {}
    cid = chat.get("id")
    if cid and cid not in seen:
        seen.add(cid)
        print(f"chat_id: {cid}  ({chat.get('first_name') or chat.get('title') or chat.get('username')})")
print("\n-> put the chat_id number in config.json (telegram_chat_id)")
