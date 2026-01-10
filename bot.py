# ============================================================
# This code is licensed under @Axcne
# Built by Axcne - All rights reserved
# Unauthorized copying, modification, or distribution is prohibited
# Contact: @Axcne on Telegram for licensing inquiries
# ============================================================

import os
import asyncio
import sys
import psutil
import random
import string
import re
from datetime import datetime, timedelta
from telethon import TelegramClient, Button, events
from telethon.sessions import StringSession
from telethon.tl.functions.account import UpdateProfileRequest
from telethon.errors import (
    SessionPasswordNeededError,
    FloodWaitError,
    PhoneNumberInvalidError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    PasswordHashInvalidError,
    ChannelPrivateError,
    ChatWriteForbiddenError,
    UserBannedInChannelError,
    MessageNotModifiedError,
    UserNotParticipantError
)
from telethon.tl.functions.channels import GetParticipantRequest
from telethon.tl.functions.messages import ForwardMessagesRequest
from telethon.tl.types import Channel, Chat, User, InputPeerChannel, InputPeerChat
from cryptography.fernet import Fernet
from pymongo import MongoClient
import time
import requests
import qrcode
import random

from config import BOT_CONFIG, FREE_TIER, PREMIUM_TIER, MESSAGES, ADMIN_SETTINGS, TOPICS, INTERVAL_PRESETS, PROXIES, FORCE_JOIN, PLANS, PLAN_IMAGE_URL, UPI_PAYMENT
import python_socks

CONFIG = BOT_CONFIG

# Helper function to get username from user ID
async def get_username_from_id(client, user_id: int):
    """Fetch username from Telegram using user ID"""
    try:
        user = await client.get_entity(user_id)
        return user.username  # None if no username
    except Exception:
        return None

def check_config():
    required = ['api_id', 'api_hash', 'bot_token', 'owner_id', 'mongo_uri']
    missing = []
    for key in required:
        val = CONFIG.get(key)
        if not val or val == '' or val == 0:
            missing.append(key.upper())
    return missing

missing_config = check_config()
if missing_config:
    print("\n" + "="*50)
    print("CONFIGURATION ERROR")
    print("="*50)
    print(f"Missing required secrets: {', '.join(missing_config)}")
    print("\nPlease add these secrets in the Secrets tab:")
    print("- TELEGRAM_API_ID")
    print("- TELEGRAM_API_HASH")
    print("- BOT_TOKEN")
    print("- OWNER_ID")
    print("- MONGO_URI")
    print("="*50)
    exit(1)

if not os.path.exists('encryption.key'):
    key = Fernet.generate_key().decode()
    with open('encryption.key', 'w') as f:
        f.write(key)
else:
    with open('encryption.key', 'r') as f:
        key = f.read().strip()
cipher_suite = Fernet(key.encode())

mongo_client = MongoClient(CONFIG['mongo_uri'])
db = mongo_client[CONFIG['db_name']]

users_col = db['users']
accounts_col = db['accounts']
account_topics_col = db['account_topics']
account_settings_col = db['account_settings']
account_stats_col = db['account_stats']
account_auto_groups_col = db['account_auto_groups']
account_failed_groups_col = db['account_failed_groups']
account_flood_waits_col = db['account_flood_waits']
logger_tokens_col = db['logger_tokens']
admins_col = db['admins']

# --- Session directory setup ---
# Always store Telethon sqlite session files inside ./session/
SESSION_DIR = 'session'
os.makedirs(SESSION_DIR, exist_ok=True)

# Migrate any legacy session files from project root into ./session/
# (e.g. main_bot.session, logger_bot.session, and their -journal files)
for _name in ('main_bot', 'logger_bot'):
    for _suffix in ('.session', '.session-journal'):
        _src = f"{_name}{_suffix}"
        _dst = os.path.join(SESSION_DIR, _src)
        try:
            if os.path.exists(_src) and not os.path.exists(_dst):
                os.replace(_src, _dst)
        except Exception:
            # Non-fatal; bot can still run
            pass

# Point Telethon at the session base path (Telethon adds .session)
main_bot = TelegramClient(os.path.join(SESSION_DIR, 'main_bot'), CONFIG['api_id'], CONFIG['api_hash'])
logger_bot = TelegramClient(os.path.join(SESSION_DIR, 'logger_bot'), CONFIG['api_id'], CONFIG['api_hash'])

# ===================== Custom Font Styling (font.txt) =====================
# font.txt contains sample text using Unicode "Mathematical Monospace" letters/digits.
# We apply the same style to all outgoing captions/messages and inline button labels.

def _load_font_sample() -> str:
    try:
        with open('font.txt', 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return ""

_FONT_SAMPLE = _load_font_sample()

# Unicode Mathematical Monospace ranges
# A-Z: U+1D670..U+1D689
# a-z: U+1D68A..U+1D6A3
# 0-9: U+1D7F6..U+1D7FF

def _to_monospace_char(ch: str) -> str:
    o = ord(ch)
    if 0x41 <= o <= 0x5A:  # A-Z
        return chr(0x1D670 + (o - 0x41))
    if 0x61 <= o <= 0x7A:  # a-z
        return chr(0x1D68A + (o - 0x61))
    if 0x30 <= o <= 0x39:  # 0-9
        return chr(0x1D7F6 + (o - 0x30))
    return ch


def _from_monospace_char(ch: str) -> str:
    """Reverse mapping for Unicode Mathematical Monospace letters/digits."""
    o = ord(ch)
    if 0x1D670 <= o <= 0x1D689:  # A-Z
        return chr(0x41 + (o - 0x1D670))
    if 0x1D68A <= o <= 0x1D6A3:  # a-z
        return chr(0x61 + (o - 0x1D68A))
    if 0x1D7F6 <= o <= 0x1D7FF:  # 0-9
        return chr(0x30 + (o - 0x1D7F6))
    return ch


def _normalize_html_tag(tag_text: str) -> str:
    """Normalize a single <...> tag by converting any monospace letters back to ASCII."""
    # Example: "<𝚋𝚕𝚘𝚌𝚔𝚚𝚞𝚘𝚝𝚎>" -> "<blockquote>"
    return ''.join(_from_monospace_char(c) for c in tag_text)


def _stylize_plain(text: str) -> str:
    if not text:
        return text
    # Only transform basic latin letters/digits. Keep emojis, punctuation, RTL, etc.
    return ''.join(_to_monospace_char(c) for c in str(text))


def _stylize_html(html: str) -> str:
    """Stylize text while preserving HTML tags/entities and leaving <code>/<pre> blocks untouched.

    Also normalizes tag names that may already be in monospace (e.g. <𝚋> -> <b>).
    """
    if not html:
        return html

    s = str(html)
    out = []

    in_entity = False
    in_code = False

    i = 0
    while i < len(s):
        ch = s[i]

        # Capture full HTML tag and normalize it (important if tag letters were stylized)
        if ch == '<':
            j = s.find('>', i + 1)
            if j == -1:
                # malformed tag; treat as plain text
                out.append(_to_monospace_char(ch) if not in_code else ch)
                i += 1
                continue

            tag = s[i:j + 1]
            norm_tag = _normalize_html_tag(tag)

            # Track <code>/<pre> blocks based on normalized tag
            lower = norm_tag.lower()
            if lower.startswith('<code'):
                in_code = True
            elif lower.startswith('</code'):
                in_code = False
            elif lower.startswith('<pre'):
                in_code = True
            elif lower.startswith('</pre'):
                in_code = False

            out.append(norm_tag)
            i = j + 1
            continue

        # Track HTML entities (&amp; etc.) so we don't corrupt them
        if ch == '&':
            in_entity = True
            out.append(ch)
            i += 1
            continue

        if in_entity:
            out.append(ch)
            if ch == ';':
                in_entity = False
            i += 1
            continue

        # Stylize only when not inside <code>/<pre>
        out.append(_to_monospace_char(ch) if not in_code else ch)
        i += 1

    return ''.join(out)


def _stylize_buttons(buttons):
    """Recursively rebuild Telethon Button structures with stylized labels."""
    if not buttons:
        return buttons

    def rebuild(btn):
        # Telethon buttons are lightweight objects created by telethon.Button
        try:
            txt = getattr(btn, 'text', None)
            data = getattr(btn, 'data', None)
            url = getattr(btn, 'url', None)

            if url is not None:
                return Button.url(_stylize_plain(txt), url)
            if data is not None:
                return Button.inline(_stylize_plain(txt), data)
        except Exception:
            return btn
        return btn

    try:
        # buttons can be a list[list[Button]] or list[Button]
        if isinstance(buttons, list):
            rebuilt = []
            for row in buttons:
                if isinstance(row, list):
                    rebuilt.append([rebuild(b) for b in row])
                else:
                    rebuilt.append(rebuild(row))
            return rebuilt
    except Exception:
        return buttons

    return buttons


def _patch_client_text_methods(client: TelegramClient):
    """Patch send_message/send_file/edit_message to stylize outgoing text/captions + button labels."""
    orig_send_message = client.send_message
    orig_send_file = client.send_file
    orig_edit_message = client.edit_message

    async def send_message_wrapped(*args, **kwargs):
        # Telethon signature: send_message(entity, message=None, ...)
        # Check for _no_style flag to bypass font transformation
        no_style = kwargs.pop('_no_style', False)
        
        if not no_style:
            if len(args) >= 2 and isinstance(args[1], str) and 'message' not in kwargs:
                parse_mode = kwargs.get('parse_mode')
                args = list(args)
                args[1] = _stylize_html(args[1]) if str(parse_mode).lower() == 'html' else _stylize_plain(args[1])
            elif isinstance(kwargs.get('message'), str):
                parse_mode = kwargs.get('parse_mode')
                kwargs['message'] = _stylize_html(kwargs['message']) if str(parse_mode).lower() == 'html' else _stylize_plain(kwargs['message'])

            if 'buttons' in kwargs:
                kwargs['buttons'] = _stylize_buttons(kwargs['buttons'])

        return await orig_send_message(*args, **kwargs)

    async def send_file_wrapped(*args, **kwargs):
        # send_file(entity, file, caption=..., ...)
        if isinstance(kwargs.get('caption'), str):
            parse_mode = kwargs.get('parse_mode')
            kwargs['caption'] = _stylize_html(kwargs['caption']) if str(parse_mode).lower() == 'html' else _stylize_plain(kwargs['caption'])

        if 'buttons' in kwargs:
            kwargs['buttons'] = _stylize_buttons(kwargs['buttons'])

        return await orig_send_file(*args, **kwargs)

    async def edit_message_wrapped(*args, **kwargs):
        # edit_message(entity, message, text=..., ...)
        parse_mode = kwargs.get('parse_mode')

        # Handle positional text argument (common when calling client.edit_message(entity, msg_id, text, ...))
        if len(args) >= 3 and isinstance(args[2], str) and 'text' not in kwargs:
            args = list(args)
            args[2] = _stylize_html(args[2]) if str(parse_mode).lower() == 'html' else _stylize_plain(args[2])

        # Handle keyword text
        if isinstance(kwargs.get('text'), str):
            kwargs['text'] = _stylize_html(kwargs['text']) if str(parse_mode).lower() == 'html' else _stylize_plain(kwargs['text'])

        if 'buttons' in kwargs:
            kwargs['buttons'] = _stylize_buttons(kwargs['buttons'])

        return await orig_edit_message(*args, **kwargs)

    client.send_message = send_message_wrapped
    client.send_file = send_file_wrapped
    client.edit_message = edit_message_wrapped


# Apply patch to both bots
_patch_client_text_methods(main_bot)
_patch_client_text_methods(logger_bot)

user_states = {}
forwarding_tasks = {}
auto_reply_clients = {}
last_replied = {}

# Payment tracking (gateway.py integration)
# (Removed) gateway payment tracking (manual UPI now)

ACCOUNTS_PER_PAGE = 7

# (Removed) External payment gateway integration
# ===================== Manual UPI Payment Helpers =====================

# In-memory pending payments
# pending_upi_payments[request_id] = {
#   'user_id': int, 'username': str|None, 'plan_key': str, 'plan_name': str,
#   'price': int, 'created_at': datetime, 'status': 'awaiting_screenshot'|'submitted'
# }
pending_upi_payments = {}

# Map admin message -> request_id so approve/reject can find it
admin_payment_message_map = {}


def _new_payment_request_id(uid: int, plan_key: str) -> str:
    # short unique id for callbacks
    return f"p{uid}_{plan_key}_{int(datetime.now().timestamp())}{random.randint(100,999)}"


def _upi_payment_caption(plan: dict, plan_key: str) -> str:
    upi_id = UPI_PAYMENT.get('upi_id', '')
    payee = UPI_PAYMENT.get('payee_name', '')
    return (
        f"<b>🧾 Manual UPI Payment</b>\n\n"
        f"<b>Plan:</b> {plan.get('name', plan_key).title()}\n"
        f"<b>Price:</b> {plan.get('price_display', plan.get('price', ''))}\n\n"
        f"<b>UPI ID:</b> <code>{_h(upi_id)}</code>\n"
        f"<b>Name:</b> {_h(payee)}\n\n"
        f"<blockquote>Scan the QR and pay. Then tap <b>Payment Done</b> and send payment screenshot.</blockquote>"
    )
# ===================== Force Join (Config-based: Channel + Group) =====================

def _forcejoin_usernames():
    # Channel-only force join
    ch = (FORCE_JOIN.get('channel_username') or '').strip().lstrip('@')
    return ch, ''

async def _is_member_of(username: str, user_id: int) -> bool:
    if not username:
        return True
    try:
        entity = await main_bot.get_entity(username)
        await main_bot(GetParticipantRequest(entity, user_id))
        return True
    except (UserNotParticipantError, ChannelPrivateError, ValueError):
        return False
    except Exception:
        # Fail-open to avoid locking everyone out if Telegram errors
        return True

async def is_user_passed_forcejoin(user_id: int) -> bool:
    if is_admin(user_id):
        return True
    if not FORCE_JOIN.get('enabled', False):
        return True

    channel_username, group_username = _forcejoin_usernames()
    # If misconfigured (missing usernames), don't block
    if not channel_username and not group_username:
        return True

    ok_channel = await _is_member_of(channel_username, user_id)
    return ok_channel

def forcejoin_keyboard():
    channel_username, _ = _forcejoin_usernames()
    buttons = []
    if channel_username:
        buttons.append([Button.url("Join Channel", f"https://t.me/{channel_username}")])
    buttons.append([Button.inline("Verify", b"force_verify")])
    return buttons

async def send_forcejoin_prompt(event, edit=False):
    msg = FORCE_JOIN.get('message') or "**Access Locked**\n\nPlease join required chats and verify."
    img = (FORCE_JOIN.get('image_url') or '').strip()

    if edit:
        # can't edit media easily; edit text only
        await event.edit(msg, buttons=forcejoin_keyboard())
        return

    if img:
        await event.respond(file=img, message=msg, buttons=forcejoin_keyboard())
    else:
        await event.respond(msg, buttons=forcejoin_keyboard())

async def enforce_forcejoin_or_prompt(event, edit=False) -> bool:
    uid = event.sender_id
    if await is_user_passed_forcejoin(uid):
        return True
    await send_forcejoin_prompt(event, edit=edit)
    return False

def is_admin(user_id):
    # Owner is always admin
    try:
        if int(user_id) == int(CONFIG['owner_id']):
            print(f"[DEBUG] User {user_id} is OWNER - Admin access granted")
            return True
        # Check if user is in admins collection
        is_db_admin = admins_col.find_one({'user_id': int(user_id)}) is not None
        print(f"[DEBUG] User {user_id} DB admin check: {is_db_admin}")
        return is_db_admin
    except Exception as e:
        print(f"[ERROR] is_admin check failed for {user_id}: {e}")
        return False

def get_user(user_id):
    user = users_col.find_one({'user_id': int(user_id)})
    if not user:
        user = {
            'user_id': int(user_id),
            'tier': 'free',
            'max_accounts': FREE_TIER['max_accounts'],
            'approved': False,
            # Premium-only feature toggle (UI in Auto Reply menu)
            'autoreply_enabled': True,
            'created_at': datetime.now()
        }
        users_col.insert_one(user)
    return user

def is_premium(user_id):
    if is_admin(user_id):
        return True
    user = get_user(user_id)
    return user.get('tier') == 'premium'

def has_per_account_config_access(user_id):
    """Check if user can access per-account config (Prime/Dominion only)."""
    if is_admin(user_id):
        return True
    user = get_user(user_id)
    # Check if user has enough accounts granted (Prime=7+, Dominion=15+)
    max_accs = user.get('max_accounts', 1)
    return max_accs >= 7  # Prime tier or higher

def get_user_tier_settings(user_id):
    if is_premium(user_id):
        return PREMIUM_TIER.copy()
    return FREE_TIER.copy()

def get_user_max_accounts(user_id):
    if is_admin(user_id):
        return 999  # Admins get unlimited accounts
    user = get_user(user_id)
    if user.get('tier') == 'premium':
        return user.get('max_accounts', PREMIUM_TIER['max_accounts'])
    return FREE_TIER['max_accounts']

def is_approved(user_id):
    if is_admin(user_id):
        return True
    user = get_user(user_id)
    return user.get('approved', False)

def approve_user(user_id):
    users_col.update_one(
        {'user_id': int(user_id)},
        {'$set': {'approved': True, 'approved_at': datetime.now()}},
        upsert=True
    )

def set_user_premium(user_id, max_accounts, plan_name='premium'):
    """Grant premium with 30-day expiry (monthly subscription)."""
    expires_at = datetime.now() + timedelta(days=30)
    users_col.update_one(
        {'user_id': int(user_id)},
        {'$set': {
            'tier': 'premium',
            'max_accounts': max_accounts,
            'plan_name': plan_name,  # Store actual plan name (Grow/Prime/Dominion)
            'premium_granted_at': datetime.now(),
            'premium_expires_at': expires_at,
            'approved': True
        }},
        upsert=True
    )

def remove_user_premium(user_id):
    users_col.update_one(
        {'user_id': int(user_id)},
        {'$set': {'tier': 'free', 'max_accounts': FREE_TIER['max_accounts']}}
    )

def get_all_users():
    return list(users_col.find({}))

def get_premium_users():
    return list(users_col.find({'tier': 'premium'}))

def get_user_accounts(user_id):
    return list(accounts_col.find({'owner_id': user_id}).sort('added_at', 1))

def get_account_by_id(account_id):
    from bson.objectid import ObjectId
    try:
        return accounts_col.find_one({'_id': ObjectId(account_id)})
    except:
        return None

def get_account_by_index(user_id, index):
    accounts = get_user_accounts(user_id)
    if 0 < index <= len(accounts):
        return accounts[index - 1]
    return None

def get_account_settings(account_id):
    settings = account_settings_col.find_one({'account_id': account_id})
    if not settings:
        settings = {
            'account_id': account_id,
            'group_delay': FREE_TIER['group_delay'],
            'msg_delay': FREE_TIER['msg_delay'],
            'round_delay': FREE_TIER['round_delay'],
            'logs_chat_id': None
        }
        account_settings_col.insert_one(settings)
    return settings

def update_account_settings(account_id, updates):
    account_settings_col.update_one(
        {'account_id': account_id},
        {'$set': updates},
        upsert=True
    )

def get_account_stats(account_id):
    stats = account_stats_col.find_one({'account_id': account_id})
    if not stats:
        stats = {'account_id': account_id, 'total_sent': 0, 'total_failed': 0, 'last_forward': None}
        account_stats_col.insert_one(stats)
    return stats

def update_account_stats(account_id, sent=0, failed=0):
    account_stats_col.update_one(
        {'account_id': account_id},
        {'$inc': {'total_sent': sent, 'total_failed': failed}, '$set': {'last_forward': datetime.now()}},
        upsert=True
    )

def is_group_failed(account_id, group_key):
    failed = account_failed_groups_col.find_one({'account_id': account_id, 'group_key': group_key})
    return failed is not None

def mark_group_failed(account_id, group_key, error):
    account_failed_groups_col.update_one(
        {'account_id': account_id, 'group_key': group_key},
        {'$set': {'error': str(error)[:200], 'failed_at': datetime.now()}},
        upsert=True
    )

def clear_failed_groups(account_id):
    account_failed_groups_col.delete_many({'account_id': account_id})

def get_flood_wait(account_id, group_key):
    doc = account_flood_waits_col.find_one({'account_id': account_id, 'group_key': group_key})
    if doc:
        wait_until = doc.get('wait_until')
        if wait_until and wait_until > datetime.now():
            remaining = (wait_until - datetime.now()).total_seconds()
            return int(remaining)
        else:
            account_flood_waits_col.delete_one({'account_id': account_id, 'group_key': group_key})
    return 0

def set_flood_wait(account_id, group_key, group_name, seconds):
    wait_until = datetime.now() + timedelta(seconds=seconds)
    account_flood_waits_col.update_one(
        {'account_id': account_id, 'group_key': group_key},
        {'$set': {
            'group_name': group_name,
            'wait_seconds': seconds,
            'wait_until': wait_until,
            'created_at': datetime.now()
        }},
        upsert=True
    )

def clear_flood_waits(account_id):
    account_flood_waits_col.delete_many({'account_id': account_id})

def get_active_flood_waits(account_id):
    now = datetime.now()
    return account_flood_waits_col.count_documents({
        'account_id': account_id,
        'wait_until': {'$gt': now}
    })

def generate_token(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

proxy_index = 0

def get_next_proxy():
    global proxy_index
    if not PROXIES:
        return None
    proxy = PROXIES[proxy_index % len(PROXIES)]
    proxy_index += 1
    
    proxy_type = python_socks.ProxyType.SOCKS5
    if proxy['type'].lower() == 'socks4':
        proxy_type = python_socks.ProxyType.SOCKS4
    elif proxy['type'].lower() == 'http':
        proxy_type = python_socks.ProxyType.HTTP
    
    return (proxy_type, proxy['host'], proxy['port'], True, proxy.get('username'), proxy.get('password'))

def parse_link(link):
    topic_id = None
    match = re.search(r'/(\d+)$', link)
    if match:
        topic_id = int(match.group(1))
    base = re.sub(r'/\d+$', '', link).rstrip('/')
    if '/c/' in base:
        cid = base.split('/c/')[-1]
        peer = int('-100' + cid)
        url = f"https://t.me/c/{cid}"
    else:
        username = base.split('t.me/')[-1]
        peer = username
        url = f"https://t.me/{username}"
    return peer, url, topic_id


def _account_id_variants(account_id):
    """Return possible stored variants for account_id field (ObjectId vs str)."""
    return [account_id, str(account_id)]

async def send_log(account_id, message, view_link=None, group_name=None):
    """Send logs via logger bot with View Message button."""
    try:
        acc_id_str = str(account_id)
        settings = get_account_settings(acc_id_str)
        chat_id = settings.get('logs_chat_id')

        if not chat_id:
            return
        
        # Use logger bot for sending logs
        if not CONFIG.get('logger_bot_token'):
            return

        if view_link and group_name:
            buttons = [[Button.url("View Message", view_link)]]
            full_msg = f"Sent to **{group_name}**"
            await logger_bot.send_message(int(chat_id), full_msg, buttons=buttons)
        elif message:
            # Handle if message is accidentally a Message object instead of string
            msg_text = str(message) if not isinstance(message, str) else message
            await logger_bot.send_message(int(chat_id), msg_text)
    except Exception as e:
        print(f"[LOG ERROR] {e}")

async def add_user_log(user_id, log_msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {log_msg}"
    users_col.update_one(
        {'user_id': user_id},
        {'$push': {'recent_logs': {'$each': [log_entry], '$slice': -100}}}
    )

async def run_forwarding_loop(user_id, account_id):
    print(f"[FORWARDING] Starting loop for account {account_id}")
    client = None
    
    try:
        acc = accounts_col.find_one({'_id': account_id})
        if not acc:
            print(f"[FORWARDING] Account {account_id} not found")
            return
        
        session = cipher_suite.decrypt(acc['session'].encode()).decode()
        client = TelegramClient(StringSession(session), CONFIG['api_id'], CONFIG['api_hash'])
        await client.connect()
        
        if not await client.is_user_authorized():
            print(f"[FORWARDING] Account {account_id} not authorized")
            return
        
        print(f"[FORWARDING] Client connected for account {account_id}")
        
        # Attach auto-reply handler to the SAME client (best practice)
        owner_id = acc.get('owner_id')
        user = get_user(owner_id)
        if user.get('autoreply_enabled', False):
            # Only use custom message - no default fallback
            settings_doc = account_settings_col.find_one({'account_id': str(account_id)})
            
            reply_text = None
            if settings_doc and 'auto_reply' in settings_doc:
                reply_text = settings_doc.get('auto_reply')
            
            if reply_text:
                @client.on(events.NewMessage(incoming=True))
                async def autoreply_handler(event):
                    # ONLY private messages
                    if not event.is_private:
                        return
                    
                    # Ignore bots
                    if isinstance(event.sender, User) and event.sender.bot:
                        return
                    
                    try:
                        await event.reply(reply_text)
                        
                        # Track auto-reply in stats
                        try:
                            account_stats_col.update_one(
                                {'account_id': str(account_id)},
                                {'$inc': {'auto_replies': 1}},
                                upsert=True
                            )
                        except Exception:
                            pass
                        
                        print(f"[AUTO-REPLY] Replied to {event.sender_id} with: {reply_text[:30]}...")
                    except Exception as e:
                        print(f"[AUTO-REPLY ERROR] {e}")
                
                print(f"[AUTO-REPLY] Attached to account {account_id} with message: {reply_text[:30]}...")
        
        while True:
            try:
                acc = accounts_col.find_one({'_id': account_id})
                if not acc or not acc.get('is_forwarding'):
                    print(f"[FORWARDING] Account {account_id} stopped")
                    break
                
                user = get_user(user_id)
                tier_settings = get_user_tier_settings(user_id)
                fwd_mode = user.get('forwarding_mode', 'topics')
                
                group_delay = tier_settings.get('group_delay', 120)
                msg_delay = tier_settings.get('msg_delay', 45)
                round_delay = tier_settings.get('round_delay', 7200)
                
                ads = []
                async for msg in client.iter_messages('me', limit=10):
                    if msg.text or msg.media:
                        ads.append(msg)
                ads.reverse()
                
                if not ads:
                    print(f"[FORWARDING] No ads in Saved Messages for {account_id}")
                    await add_user_log(user_id, "No ads in Saved Messages - add messages to Saved Messages")
                    await asyncio.sleep(60)
                    continue
                
                print(f"[FORWARDING] Loaded {len(ads)} ads from Saved Messages")
                
                groups_to_forward = []
                
                acc_id_str = str(account_id)
                
                if fwd_mode in ('topics', 'both'):
                    topic_groups = list(account_topics_col.find({'account_id': acc_id_str}))
                    if not topic_groups:
                        topic_groups = list(account_topics_col.find({'account_id': account_id}))
                    
                    for tg in topic_groups:
                        link = tg.get('link') or tg.get('url')
                        if link and 't.me/' in link:
                            if '?' in link:
                                link = link.split('?')[0]
                            peer, url, topic_id = parse_link(link)
                            group_key = link
                            if not is_group_failed(acc_id_str, group_key):
                                groups_to_forward.append({
                                    'peer': peer,
                                    'url': url,
                                    'topic_id': topic_id,
                                    'title': tg.get('title', link.split('/')[-2] if '/' in link else 'Unknown'),
                                    'type': 'topic',
                                    'key': group_key
                                })
                    print(f"[FORWARDING] Added {len(groups_to_forward)} topic groups")
                
                if fwd_mode in ('auto', 'both'):
                    auto_groups = list(account_auto_groups_col.find({'account_id': acc_id_str}))
                    if not auto_groups:
                        auto_groups = list(account_auto_groups_col.find({'account_id': account_id}))
                    
                    count = 0
                    for ag in auto_groups:
                        group_key = str(ag['group_id'])
                        if not is_group_failed(acc_id_str, group_key):
                            groups_to_forward.append({
                                'group_id': ag['group_id'],
                                'access_hash': ag.get('access_hash'),
                                'username': ag.get('username'),
                                'title': ag.get('title', 'Unknown'),
                                'type': 'auto',
                                'key': group_key
                            })
                            count += 1
                    print(f"[FORWARDING] Added {count} auto groups")
                
                if not groups_to_forward:
                    print(f"[FORWARDING] No groups to forward to")
                    await add_user_log(user_id, "No groups configured - waiting")
                    await asyncio.sleep(60)
                    continue
                
                sent = 0
                failed = 0
                skipped = 0
                
                for i, group in enumerate(groups_to_forward):
                    acc = accounts_col.find_one({'_id': account_id})
                    if not acc or not acc.get('is_forwarding'):
                        break
                    
                    group_key = group.get('key', group.get('title', 'unknown'))
                    wait_remaining = get_flood_wait(account_id, group_key)
                    if wait_remaining > 0:
                        skipped += 1
                        print(f"[FORWARDING] Skipped {group['title']} (flood wait: {wait_remaining // 60}m)")
                        continue
                    
                    msg = ads[i % len(ads)]
                    
                    try:
                        sent_msg_id = None
                        current_entity = None
                        current_topic_id = None
                        
                        if group['type'] == 'topic':
                            peer = group['peer']
                            current_topic_id = group.get('topic_id')
                            current_entity = None
                            
                            try:
                                if isinstance(peer, str):
                                    current_entity = await client.get_entity(peer)
                                elif isinstance(peer, int):
                                    if peer > 0:
                                        peer = int('-100' + str(peer))
                                    current_entity = await client.get_entity(peer)
                            except:
                                pass
                            
                            if current_entity is None:
                                raise Exception(f"Cannot resolve topic peer: {peer}")
                            
                            group_name = getattr(current_entity, 'title', group['title'])[:30]
                            
                            if current_topic_id:
                                sent_msg_id = await forward_message(client, current_entity, msg.id, msg.peer_id, current_topic_id)
                            else:
                                result = await client.forward_messages(current_entity, msg.id, 'me')
                                if result:
                                        if isinstance(result, list):
                                            sent_msg_id = result[0].id if len(result) > 0 else None

                                        else:


                                            sent_msg_id = result.id
                        else:
                            current_entity = None
                            group_id = group['group_id']
                            
                            if group.get('username'):
                                try:
                                    current_entity = await client.get_entity(group['username'])
                                except:
                                    pass
                            
                            if current_entity is None:
                                try:
                                    full_id = int('-100' + str(abs(group_id))) if group_id > 0 else group_id
                                    current_entity = await client.get_entity(full_id)
                                except:
                                    pass
                            
                            if current_entity is None and group.get('access_hash'):
                                try:
                                    current_entity = InputPeerChannel(channel_id=abs(group_id), access_hash=group['access_hash'])
                                except:
                                    pass
                            
                            if current_entity is None:
                                raise Exception(f"Cannot resolve entity for group {group_id}")
                            
                            group_name = group['title'][:30]
                            result = await client.forward_messages(current_entity, msg.id, 'me')
                            if result:
                                if result:
                                    if isinstance(result, list):
                                        sent_msg_id = result[0].id if len(result) > 0 else None
                                    else:
                                        sent_msg_id = result.id

                                    sent_msg_id = result.id
                        
                        sent += 1
                        print(f"[FORWARDING] Sent to {group_name} ({i+1}/{len(groups_to_forward)})")
                        await add_user_log(user_id, f"Sent to {group_name}")
                        
                        # Send logs (now free for everyone)
                        if sent_msg_id and current_entity:
                            view_link = build_message_link(current_entity, sent_msg_id, current_topic_id)
                            if view_link:
                                await send_log(account_id, None, view_link=view_link, group_name=group_name)
                        
                        # Update stats in correct collection
                        update_account_stats(str(account_id), sent=1)
                        
                    except FloodWaitError as e:
                        wait_time = e.seconds
                        failed += 1
                        set_flood_wait(account_id, group_key, group['title'], wait_time)
                        print(f"[FORWARDING] FloodWait {wait_time // 60}m for {group['title']} - will skip until expires")
                        await add_user_log(user_id, f"FloodWait {wait_time // 60}m in {group['title'][:20]}")
                        
                    except (ChannelPrivateError, ChatWriteForbiddenError, UserBannedInChannelError) as e:
                        failed += 1
                        mark_group_failed(account_id, group_key, str(e))
                        print(f"[FORWARDING] Permanent fail {group['title']}: {type(e).__name__}")
                        
                    except Exception as e:
                        failed += 1
                        error_str = str(e)
                        wait_match = re.search(r'wait of (\d+) seconds', error_str, re.IGNORECASE)
                        if wait_match:
                            wait_time = int(wait_match.group(1))
                            set_flood_wait(account_id, group_key, group['title'], wait_time)
                        else:
                            print(f"[FORWARDING] Error {group['title']}: {error_str[:50]}")
                        # Update stats in correct collection
                        update_account_stats(str(account_id), failed=1)
                    
                    await asyncio.sleep(msg_delay)
                    
                    if (i + 1) % 10 == 0:
                        await asyncio.sleep(group_delay)
                
                print(f"[FORWARDING] Round complete. Sent: {sent}, Failed: {failed}, Skipped: {skipped}")
                await add_user_log(user_id, f"Round: {sent} sent, {failed} failed, {skipped} skipped")
                
                print(f"[FORWARDING] Waiting {round_delay}s for next round...")
                await asyncio.sleep(round_delay)
                
            except asyncio.CancelledError:
                print(f"[FORWARDING] Task cancelled for account {account_id}")
                break
        
    except asyncio.CancelledError:
        print(f"[FORWARDING] Task cancelled for account {account_id}")
    except Exception as e:
        print(f"[FORWARDING] Error in loop: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if client:
            try:
                await client.disconnect()
                print(f"[FORWARDING] Client disconnected for account {account_id}")
            except:
                pass
        if account_id in forwarding_tasks:
            del forwarding_tasks[account_id]

async def forward_message(client, to_entity, msg_id, from_peer, topic_id=None):
    random_id = random.randint(1, 2147483647)
    result = await client(ForwardMessagesRequest(
        from_peer=from_peer,
        id=[msg_id],
        random_id=[random_id],
        to_peer=to_entity,
        top_msg_id=topic_id
    ))
    if result.updates:
        for update in result.updates:
            if hasattr(update, 'message') and hasattr(update.message, 'id'):
                return update.message.id
    return None

def build_message_link(entity, msg_id, topic_id=None):
    username = getattr(entity, 'username', None)
    if username:
        base = f"https://t.me/{username}"
    else:
        chat_id = getattr(entity, 'id', None)
        if chat_id:
            base = f"https://t.me/c/{chat_id}"
        else:
            return None
    
    if topic_id:
        return f"{base}/{topic_id}/{msg_id}" if msg_id else f"{base}/{topic_id}"
    return f"{base}/{msg_id}" if msg_id else base

async def fetch_groups(client, account_id, phone):
    try:
        dialogs = await client.get_dialogs(limit=None)
        groups = []
        for d in dialogs:
            e = d.entity
            if isinstance(e, User):
                continue
            if not isinstance(e, (Channel, Chat)):
                continue
            if isinstance(e, Channel) and e.broadcast:
                continue
            title = getattr(e, 'title', 'Unknown')
            if title and title != 'Unknown':
                group_id = e.id
                access_hash = getattr(e, 'access_hash', None)
                username = getattr(e, 'username', None)
                is_channel = isinstance(e, Channel)
                
                if access_hash is None and is_channel:
                    try:
                        full_entity = await client.get_entity(e)
                        access_hash = getattr(full_entity, 'access_hash', None)
                    except:
                        pass
                
                groups.append({
                    'account_id': account_id,
                    'phone': phone,
                    'group_id': group_id,
                    'title': title,
                    'username': username,
                    'access_hash': access_hash,
                    'is_channel': is_channel,
                    'added_at': datetime.now()
                })
        if groups:
            account_auto_groups_col.delete_many({'account_id': account_id})
            account_auto_groups_col.insert_many(groups)
        return len(groups)
    except Exception as e:
        print(f"Fetch groups error: {e}")
        return 0

# ===================== UI Helpers =====================

def _h(s: str) -> str:
    """Basic HTML escape for user-provided strings."""
    try:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
    except Exception:
        return ""


def ui_title(title: str) -> str:
    return f"<b>{_h(title)}</b>"


def ui_kv(key: str, val: str) -> str:
    return f"<b>{_h(key)}:</b> {_h(val)}"


def ui_section(title: str, lines: list[str]) -> str:
    body = "\n".join(lines).strip()
    return f"<b>{_h(title)}</b>\n{body}" if body else f"<b>{_h(title)}</b>"


def ui_divider() -> str:
    return "\n\n"


def render_plan_select_text() -> str:
    return (
        "<b>💎 Choose Your Plan</b>\n\n"
        "<blockquote>Pick a plan that matches your needs. You can upgrade anytime.</blockquote>\n\n"
        "<b>Plans:</b> Scout (Free) • Grow • Prime • Dominion"
    )


def render_welcome_text() -> str:
    return (
        "🚀 Welcome to Kabru Ads Bot\n\n"
        "Automate your Telegram advertising campaigns across multiple groups.\n\n"
        "Get started: Tap Kabru Ads Now to choose a plan and add your first account."
    )


def render_dashboard_text(uid: int) -> str:
    user = get_user(uid)
    max_acc = user.get('max_accounts', 1)
    
    # Determine plan name and expiry
    if is_admin(uid):
        plan_name = "Admin"
        max_acc = 999
        expiry_text = "999d"
    elif is_premium(uid):
        # Use stored plan_name if available, otherwise derive from max_accounts
        plan_name = user.get('plan_name', 'Premium')
        if not user.get('plan_name'):
            # Backward compatibility: derive from max_accounts
            if max_acc >= 15:
                plan_name = "Dominion"
            elif max_acc >= 7:
                plan_name = "Prime"
            else:
                plan_name = "Grow"
        
        # Calculate expiry countdown
        expires_at = user.get('premium_expires_at')
        if expires_at and isinstance(expires_at, datetime):
            remaining = expires_at - datetime.now()
            if remaining.total_seconds() > 0:
                days_left = remaining.days
                expiry_text = f"{days_left}d"
            else:
                expiry_text = "Expired"
        else:
            expiry_text = "∞"  # Legacy users without expiry
    else:
        plan_name = "Scout: Free"
        expiry_text = "∞"
    
    accounts = get_user_accounts(uid)
    active = sum(1 for a in accounts if a.get('is_forwarding'))
    mode = user.get('forwarding_mode', 'topics')
    preset = user.get('interval_preset', 'medium')

    return (
        "<b>📊 Dashboard</b>\n\n"
        + "\n".join([
            ui_kv("Plan", f"{plan_name} ({expiry_text})"),
            ui_kv("Accounts", f"{len(accounts)}/{max_acc} (active: {active})"),
            ui_kv("Mode", mode),
            ui_kv("Intervals", preset),
        ])
        + "\n\n<i>Use the menu below to manage accounts and start ads.</i>"
    )


# ===================== Keyboards =====================

def new_welcome_keyboard():
    """New welcome screen with single Kabru Ads Now button."""
    return [
        [Button.inline("Kabru Ads Now", b"adsye_now")],
        [Button.url("Support", MESSAGES['support_link']), Button.url("Updates", MESSAGES['updates_link'])]
    ]

def plan_select_keyboard(user_id=None):
    """Plan selection: Scout, Grow, Prime, Dominion (2x2 grid layout)."""
    user = get_user(user_id) if user_id else None
    user_plan = user.get('plan_name', '').lower() if user else None
    is_prem = is_premium(user_id) if user_id else False
    
    # Check if premium has expired
    if is_prem and user:
        expires_at = user.get('premium_expires_at')
        if expires_at and isinstance(expires_at, datetime):
            if expires_at < datetime.now():
                # Premium expired - reset to Scout
                is_prem = False
                user_plan = 'scout'
    
    buttons = []
    
    # First row: Scout + Grow (hide Scout for active premium users)
    row1 = []
    if not is_prem:
        scout_label = "✓ Scout (Active)" if user_plan == 'scout' else "Scout (Free)"
        row1.append(Button.inline(scout_label, b"plan_scout"))
    
    # Show "✓ Active" if user has this plan
    grow_label = "✓ Grow (Active)" if user_plan == 'grow' and is_prem else f"Grow ({PLANS['grow']['price_display']})"
    row1.append(Button.inline(grow_label, b"plan_grow"))
    buttons.append(row1)
    
    # Second row: Prime + Dominion
    prime_label = "✓ Prime (Active)" if user_plan == 'prime' and is_prem else f"Prime ({PLANS['prime']['price_display']})"
    dominion_label = "✓ Dominion (Active)" if user_plan == 'dominion' and is_prem else f"Dominion ({PLANS['dominion']['price_display']})"
    buttons.append([
        Button.inline(prime_label, b"plan_prime"),
        Button.inline(dominion_label, b"plan_dominion")
    ])
    
    # Dashboard button
    buttons.append([Button.inline("🏠 Dashboard", b"enter_dashboard")])
    
    return buttons

def tier_selection_keyboard():
    return [
        [Button.inline("Free", b"tier_free"), Button.inline("Premium", b"tier_premium")],
        [Button.inline("Back", b"back_start")]
    ]

def main_dashboard_keyboard(user_id):
    accounts = get_user_accounts(user_id)
    has_active = any(acc.get('is_forwarding') for acc in accounts)
    ads_btn = "\u23F9\uFE0F Stop Ads" if has_active else "\u25B6\uFE0F Start Ads"  # ⏹️ / ▶️
    ads_data = b"stop_all_ads" if has_active else b"start_all_ads"

    buttons = [
        [Button.inline("\U0001F4CB Accounts", b"menu_account"), Button.inline("\U0001F4CA Analytics", b"menu_analytics")],  # 📋 📊
        [Button.inline("\u23F1\uFE0F Intervals", b"menu_interval"), Button.inline("\U0001F504 Fwd Mode", b"menu_fwd_mode")],  # ⏱️ 🔄
    ]

    # Settings and Plans row
    buttons.append([
        Button.inline("\u2699\uFE0F Settings", b"menu_settings"),  # ⚙️
        Button.inline("\U0001F48E Plans", b"back_plans"),          # 💎
    ])
    
    # Row 3: Start Ads button + Admin button (for admins only)
    if is_admin(user_id):
        buttons.append([Button.inline(ads_btn, ads_data), Button.inline("\u2699\uFE0F Admin", b"admin_panel")])
    else:
        buttons.append([Button.inline(ads_btn, ads_data)])
    
    return buttons

def account_list_keyboard(user_id, page=0):
    accounts = get_user_accounts(user_id)
    max_accounts = get_user_max_accounts(user_id)
    total = len(accounts)
    pages = max(1, (total + ACCOUNTS_PER_PAGE - 1) // ACCOUNTS_PER_PAGE)
    
    start = page * ACCOUNTS_PER_PAGE
    end = min(start + ACCOUNTS_PER_PAGE, total)
    page_accounts = accounts[start:end]
    
    buttons = []
    for i, acc in enumerate(page_accounts):
        idx = start + i + 1
        phone = acc['phone']
        name = acc.get('name', 'Unknown')[:12]
        status = "Active" if acc.get('is_forwarding') else "Inactive"
        buttons.append([Button.inline(f"{status} #{idx} {phone[-4:]} - {name}", f"acc_{acc['_id']}")])
    
    nav = []
    if page > 0:
        nav.append(Button.inline("Prev", f"accpage_{page-1}"))
    if page < pages - 1:
        nav.append(Button.inline("Next", f"accpage_{page+1}"))
    if nav:
        buttons.append(nav)
    
    if total >= max_accounts:
        buttons.append([Button.inline("+ Add Account (Locked)", b"account_limit_reached"), Button.inline("Delete Account", b"delete_account_menu")])
    else:
        buttons.append([Button.inline("+ Add Account", b"add_account"), Button.inline("Delete Account", b"delete_account_menu")])
    buttons.append([Button.inline("Back", b"enter_dashboard")])
    
    return buttons

def settings_menu_keyboard(uid):
    """Settings menu with Auto Reply, Topics, Logs, Smart Rotation, Auto Group Join."""
    # Use Unicode escape sequences to avoid any editor/encoding corruption
    buttons = [
        [Button.inline("\U0001F4AC Auto Reply", b"menu_autoreply")],  # 💬
        [Button.inline("\U0001F4C2 Topics", b"menu_topics")],        # 📂
        [Button.inline("\U0001F4DD Logs", b"menu_logs")],            # 📝
    ]
    
    # Premium-only features
    if is_premium(uid):
        buttons.append([Button.inline("\U0001F504 Smart Rotation", b"menu_smart_rotation")])  # 🔄
        buttons.append([Button.inline("\U0001F465 Auto Group Join", b"menu_auto_group_join")])  # 👥
    
    buttons.append([Button.inline("\u2190 Back", b"enter_dashboard")])  # ←
    return buttons
def interval_menu_keyboard(user_id):
    user = get_user(user_id)
    current = user.get('interval_preset', 'medium')

    def mark_for(key: str) -> str:
        return " ✓" if key == current else ""

    # Keep 2 buttons per row: Slow/Medium + Fast/Custom
    slow = Button.inline(f"{INTERVAL_PRESETS['slow']['name']}{mark_for('slow')}", b"interval_slow")
    medium = Button.inline(f"{INTERVAL_PRESETS['medium']['name']}{mark_for('medium')}", b"interval_medium")
    fast = Button.inline(f"{INTERVAL_PRESETS['fast']['name']}{mark_for('fast')}", b"interval_fast")

    if is_premium(user_id):
        custom_mark = " ✓" if current == 'custom' else ""
        custom = Button.inline(f"Custom Settings{custom_mark}", b"interval_custom")
    else:
        custom = Button.inline("Custom (Premium Only)", b"interval_upgrade")

    return [
        [slow, medium],
        [fast, custom],
        [Button.inline("Back", b"enter_dashboard")],
    ]

def autoreply_menu_keyboard(user_id):
    if is_premium(user_id):
        user = get_user(user_id)
        enabled = user.get('autoreply_enabled', True)
        
        # Check if user has set a custom message
        accounts = get_user_accounts(user_id)
        has_custom = False
        if accounts:
            for acc in accounts:
                settings_doc = account_settings_col.find_one({'account_id': str(acc['_id'])})
                if settings_doc and 'auto_reply' in settings_doc and settings_doc.get('auto_reply'):
                    has_custom = True
                    break
        
        # Single toggle button: show the opposite action only
        toggle_btn = Button.inline("Turn OFF" if enabled else "Turn ON", b"autoreply_toggle")
        buttons = [[toggle_btn]]
        
        # Only show "View Current" if custom message is set
        if has_custom:
            buttons.append([Button.inline("View Current", b"autoreply_view")])
        
        buttons.append([Button.inline("Set Custom Reply", b"autoreply_custom")])
        buttons.append([Button.inline("← Back", b"menu_settings")])
    else:
        # Free users - auto-reply locked
        buttons = [
            [Button.inline("🔒 Locked - Premium Only", b"go_premium")],
            [Button.inline("← Back", b"menu_settings")]
        ]
    return buttons

def delete_account_list_keyboard(user_id):
    accounts = get_user_accounts(user_id)
    buttons = []
    for acc in accounts:
        phone = acc['phone']
        name = acc.get('name', 'Unknown')[:12]
        buttons.append([Button.inline(f"Delete: {phone[-4:]} - {name}", f"confirm_del_{acc['_id']}")])
    buttons.append([Button.inline("Back", b"menu_account")])
    return buttons

def premium_contact_keyboard():
    return [
        [Button.url("Contact Admin", MESSAGES['support_link'])],
        [Button.inline("Back", b"enter_dashboard")]
    ]


async def apply_account_profile_templates(user_id: int):
    """Update all added accounts' profile last name + bio using templates from config.

    - First name is kept as-is
    - Last name forced to MESSAGES['account_last_name_tag']
    - Bio forced to MESSAGES['account_bio']
    """
    try:
        last_name = MESSAGES.get('account_last_name_tag', '')
        about = MESSAGES.get('account_bio', '')
        if not last_name and not about:
            return

        accounts = list(accounts_col.find({'owner_id': int(user_id)}))
        for acc in accounts:
            session = acc.get('session')
            if not session:
                continue

            # DECRYPT session before using it
            try:
                decrypted_session = cipher_suite.decrypt(session.encode()).decode()
            except Exception:
                continue

            client = TelegramClient(StringSession(decrypted_session), CONFIG['api_id'], CONFIG['api_hash'])
            try:
                await client.connect()
                me = await client.get_me()
                first_name = me.first_name or ''

                await client(UpdateProfileRequest(
                    first_name=first_name,
                    last_name=last_name,
                    about=about,
                ))
            except Exception:
                pass
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
    except Exception:
        return

def admin_panel_keyboard():
    # Layout requested:
    # Row 1: All Users | Premium Users
    # Row 2: Full Stats | Grant Premium
    # Row 3: Back
    return [
        [Button.inline("All Users", b"admin_all_users"), Button.inline("Premium Users", b"admin_premium")],
        [Button.inline("Full Stats", b"admin_users"), Button.inline("Grant Premium", b"admin_grant_premium")],
        [Button.inline("Back", b"enter_dashboard")]
    ]

def account_menu_keyboard(account_id, acc, user_id):
    fwd = acc.get('is_forwarding', False)
    btn = "Stop" if fwd else "Start"
    data = f"stop_{account_id}" if fwd else f"fwd_select_{account_id}"
    
    tier_settings = get_user_tier_settings(user_id)
    buttons = [
        [Button.inline("Topics", f"topics_{account_id}"), Button.inline("Settings", f"settings_{account_id}")],
        [Button.inline("Stats", f"stats_{account_id}"), Button.inline("Refresh", f"refresh_{account_id}")],
        [Button.inline(btn, data)],
        [Button.inline("Delete", f"delete_{account_id}")]
    ]
    
    if tier_settings.get('logs_enabled'):
        buttons.insert(3, [Button.inline("Logs", f"logs_{account_id}")])
    
    buttons.append([Button.inline("Back", b"tier_free")])
    return buttons

def topics_menu_keyboard(account_id, user_id):
    tier_settings = get_user_tier_settings(user_id)
    max_topics = tier_settings.get('max_topics', 3)
    
    buttons = []
    row = []
    for i, t in enumerate(TOPICS[:max_topics]):
        count = account_topics_col.count_documents({'account_id': account_id, 'topic': t})
        row.append(Button.inline(f"{t.capitalize()} ({count})", f"topic_{account_id}_{t}"))
        
        # Add row when we have 3 buttons or it's the last topic
        if len(row) == 3 or i == max_topics - 1:
            buttons.append(row)
            row = []
    
    auto = account_auto_groups_col.count_documents({'account_id': account_id})
    buttons.append([Button.inline(f"Auto Groups ({auto})", f"auto_{account_id}")])
    buttons.append([Button.inline("Back", f"acc_{account_id}")])
    return buttons

def forwarding_select_keyboard(account_id, user_id):
    tier_settings = get_user_tier_settings(user_id)
    max_topics = tier_settings.get('max_topics', 3)
    
    buttons = []
    for t in TOPICS[:max_topics]:
        count = account_topics_col.count_documents({'account_id': account_id, 'topic': t})
        if count > 0:
            buttons.append([Button.inline(f"{t.capitalize()} ({count})", f"startfwd_{account_id}_{t}")])
    buttons.append([Button.inline("All Groups Only", f"startfwd_{account_id}_all")])
    buttons.append([Button.inline("Cancel", f"acc_{account_id}")])
    return buttons

def settings_keyboard(account_id, user_id):
    tier_settings = get_user_tier_settings(user_id)
    buttons = [
        [Button.inline("Msg Delay", f"setmsg_{account_id}"), Button.inline("Group Delay", f"setgrp_{account_id}")],
        [Button.inline("Round Delay", f"setround_{account_id}")],
        [Button.inline("Clear Failed", f"clearfailed_{account_id}")]
    ]
    
    if tier_settings.get('auto_reply_enabled'):
        buttons.insert(2, [Button.inline("Auto-Reply", f"setreply_{account_id}")])
    
    buttons.append([Button.inline("Back", f"acc_{account_id}")])
    return buttons

def otp_keyboard():
    return [
        [Button.inline("1", b"otp_1"), Button.inline("2", b"otp_2"), Button.inline("3", b"otp_3")],
        [Button.inline("4", b"otp_4"), Button.inline("5", b"otp_5"), Button.inline("6", b"otp_6")],
        [Button.inline("7", b"otp_7"), Button.inline("8", b"otp_8"), Button.inline("9", b"otp_9")],
        [Button.inline("Del", b"otp_back"), Button.inline("0", b"otp_0"), Button.inline("X", b"otp_cancel")],
        [Button.url("Get Code", "tg://openmessage?user_id=777000")]
    ]

@main_bot.on(events.NewMessage(pattern=r'^/start(?:@[\w_]+)?(?:\s|$)'))
async def cmd_start(event):
    uid = event.sender_id
    get_user(uid)

    # Force-join gate (admin bypass)
    if not await enforce_forcejoin_or_prompt(event):
        return

    approve_user(uid)

    # Check if user has accounts
    accounts = get_user_accounts(uid)
    
    # If user activated any plan (free or premium), always show dashboard
    if is_approved(uid):
        # User has plan activated, show dashboard with welcome image
        dashboard_text = render_dashboard_text(uid)
        dashboard_buttons = main_dashboard_keyboard(uid)
        welcome_image = MESSAGES.get('welcome_image', '')
        
        if welcome_image:
            await event.respond(file=welcome_image, message=dashboard_text, parse_mode='html', buttons=dashboard_buttons)
        else:
            await event.respond(dashboard_text, parse_mode='html', buttons=dashboard_buttons)
    elif len(accounts) > 0:
        # User has accounts but no plan selected yet, show plan selection
        plan_msg = render_plan_select_text()
        
        if PLAN_IMAGE_URL:
            await event.respond(file=PLAN_IMAGE_URL, message=plan_msg, buttons=plan_select_keyboard(uid))
        else:
            await event.respond(plan_msg, buttons=plan_select_keyboard(uid))
    else:
        # No accounts, show welcome screen
        welcome_text = render_welcome_text()
        
        welcome_image = MESSAGES.get('welcome_image', '')
        if welcome_image:
            await event.respond(
                file=welcome_image,
                message=welcome_text,
                buttons=new_welcome_keyboard()
            )
        else:
            await event.respond(
                welcome_text,
                buttons=new_welcome_keyboard()
            )

@main_bot.on(events.NewMessage(pattern=r'^/access(?:@[\w_]+)?\s+(.+)$'))
async def cmd_access(event):
    uid = event.sender_id
    pwd = event.pattern_match.group(1).strip()
    
    if pwd == CONFIG['access_password'] or is_admin(uid):
        approve_user(uid)
        await event.respond("Access granted!", buttons=new_welcome_keyboard())
    else:
        await event.respond("Wrong password!")

@main_bot.on(events.NewMessage(pattern=r'^/admin(?:@[\w_]+)?(?:\s|$)'))
async def cmd_admin_panel(event):
    """Admin: Show Kabru Ads-style admin panel."""
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    # Get stats
    total_users = users_col.count_documents({})
    premium_users = users_col.count_documents({'tier': 'premium'})
    total_accounts = accounts_col.count_documents({})
    active_accounts = accounts_col.count_documents({'is_forwarding': True})
    total_admins = admins_col.count_documents({}) + 1
    
    # Today's new users
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    new_today = users_col.count_documents({'created_at': {'$gte': today_start}}) if users_col.find_one({}, {'created_at': 1}) else 0
    
    # Current time
    now = datetime.now().strftime("%d/%m/%y • %I:%M %p")
    
    text = (
        f"<b>✦ KABRU ADS ADMIN CONTROL CENTER</b>\n\n"
        f"<code>Time: {now}</code>\n\n"
        f"<b>[stats]</b> QUICK STATS:\n"
        f"<code>├ Users: {total_users} | Premium: {premium_users}\n"
        f"├ Accounts: {total_accounts} | Active: {active_accounts}\n"
        f"└ Admins: {total_admins} | New Today: {new_today}</code>\n\n"
        f"<i>Select a section below to manage</i>"
    )
    
    buttons = [
        [Button.inline("👥 Users", b"admin_users"), Button.inline("👑 Admins", b"admin_admins")],
        [Button.inline("📊 Stats", b"admin_stats"), Button.inline("🔧 Controls", b"admin_controls")],
        [Button.inline("← Back", b"back_start")]
    ]
    
    await event.respond(text, parse_mode='html', buttons=buttons)

@main_bot.on(events.NewMessage(pattern=r'^/help(?:@[\w_]+)?(?:\s|$)'))
async def cmd_help(event):
    uid = event.sender_id

    if not await enforce_forcejoin_or_prompt(event):
        return

    text = (
        "<b>⚡ KABRU ADS BOT COMMANDS</b>\n\n"
        "<b>🎯 User Commands:</b>\n"
        "<code>/start</code> — Start the bot\n"
        "<code>/add</code> — Quick add account\n"
        "<code>/go</code> or <code>/run</code> — Instantly start ads\n"
        "<code>/stop</code> — Instantly stop ads\n"
        "<code>/status</code> — View broadcast status\n"
        "<code>/me</code> — View your profile\n"
        "<code>/help</code> — Show this help menu\n\n"
        "<b>💡 Quick Tips:</b>\n"
        "<code>• Use /add to quickly add accounts\n"
        "• Use /go to start broadcasting\n"
        "• Use /stop to halt all broadcasts</code>\n"
    )
    
    if is_admin(uid):
        text += (
            "\n<b>⚙️ Admin Commands:</b>\n"
            "<code>/admin</code> — Admin panel\n"
            "<code>/addadmin {id}</code> — Add new admin\n"
            "<code>/rmadmin {id}</code> — Remove admin\n"
            "<code>/finduser {id}</code> — View user details\n"
            "<code>/ping</code> — VPS stats\n"
            "<code>/stats</code> — Admin bot stats\n"
            "<code>/bd</code> — Broadcast to all users\n"
        )
    
    buttons = [
        [Button.url("📞 Support", MESSAGES['support_link']), Button.url("📢 Updates", MESSAGES['updates_link'])]
    ]
    
    await event.respond(text, parse_mode='html', buttons=buttons)

@main_bot.on(events.NewMessage(pattern=r'^/rmprm(?:@[\w_]+)?\s+(\d+)$'))
async def cmd_rmprm(event):
    uid = event.sender_id
    if not is_admin(uid):
        await event.respond("Admin only!")
        return
    
    target_id = int(event.pattern_match.group(1))
    remove_user_premium(target_id)
    
    await event.respond(f"Premium removed from {target_id}")

@main_bot.on(events.NewMessage(pattern=r'^/users(?:@[\w_]+)?(?:\s|$)'))
async def cmd_users(event):
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    users = get_all_users()
    if not users:
        await event.respond("No users.")
        return
    
    text = "**All Users**\n\n"
    for u in users[:50]:
        user_id = u.get('user_id')
        tier = u.get('tier', 'free')
        tier_icon = "P" if tier == 'premium' else "F"
        max_acc = u.get('max_accounts', FREE_TIER['max_accounts'])
        accounts = accounts_col.count_documents({'owner_id': user_id})
        is_owner = " (Admin)" if user_id == CONFIG['owner_id'] else ""
        text += f"[{tier_icon}] `{user_id}` - {accounts}/{max_acc} acc{is_owner}\n"
    
    if len(users) > 50:
        text += f"\n...+{len(users)-50} more"
    
    await event.respond(text)

@main_bot.on(events.NewMessage(pattern=r'^/clearusers(?:@[\w_]+)?(?:\s|$)'))
async def cmd_clearusers(event):
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    result = users_col.delete_many({'user_id': {'$ne': int(uid)}})
    approve_user(uid)
    
    await event.respond(f"Cleared {result.deleted_count} users!")

@main_bot.on(events.NewMessage(pattern=r'^/ping(?:@[\w_]+)?(?:\s|$)'))
async def cmd_ping(event):
    """Admin: Show Kabru Ads-style system stats."""
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    import platform
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    uptime_sec = int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds())
    uptime_str = f"{uptime_sec//3600:02d}:{(uptime_sec%3600)//60:02d}:{uptime_sec%60:02d}"
    
    # Bot stats
    total_users = users_col.count_documents({})
    active_accounts = accounts_col.count_documents({'is_forwarding': True})
    total_accounts = accounts_col.count_documents({})
    
    text = (
        f"<b>PONG! — BOT STATUS</b>\n\n"
        f"<code> System: {platform.system()} {platform.release()}\n"
        f" Uptime: {uptime_str}\n\n"
        f" CPU Usage: {cpu}%\n"
        f" RAM: {ram.percent}% ({ram.used//(1024**3)}GB / {ram.total//(1024**3)}GB)\n"
        f" Disk: {disk.percent}% ({disk.used//(1024**3)}GB / {disk.total//(1024**3)}GB)</code>\n\n"
        f"<b>[stats]</b> Bot Stats:\n"
        f"<code>• Active Broadcasts: {active_accounts}\n"
        f"• Total Users: {total_users}\n"
        f"• Active Accounts: {total_accounts}</code>\n\n"
        f"<i>Bot is running smoothly!</i> <b>[OK]</b>"
    )
    
    await event.respond(text, parse_mode='html')

@main_bot.on(events.NewMessage(pattern=r'^/reboot(?:@[\w_]+)?(?:\s|$)'))
async def cmd_reboot(event):
    """Admin: Reboot the bot (restart process)."""
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    await event.respond("🔄 Rebooting bot...")
    
    # Restart the process
    os.execv(sys.executable, ['python'] + sys.argv)

@main_bot.on(events.NewMessage(pattern=r'^/addadmin(?:@[\w_]+)?\s+(\d+)$'))
async def cmd_addadmin(event):
    """Admin: Add admin."""
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    target_uid = int(event.pattern_match.group(1))
    
    # Check if already admin
    if admins_col.find_one({'user_id': target_uid}):
        await event.respond(f"`{target_uid}` is already an admin!")
        return
    
    # Add to admins
    admins_col.insert_one({'user_id': target_uid, 'added_at': datetime.now(), 'added_by': uid})
    
    # Notify
    try:
        await main_bot.send_message(target_uid, "🎉 You've been granted admin access!")
    except:
        pass
    
    await event.respond(f"✅ Added `{target_uid}` as admin!")

@main_bot.on(events.NewMessage(pattern=r'^/rmadmin(?:@[\w_]+)?\s+(\d+)$'))
async def cmd_rmadmin(event):
    """Admin: Remove admin."""
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    target_uid = int(event.pattern_match.group(1))
    
    # Cannot remove owner
    if target_uid == CONFIG['owner_id']:
        await event.respond("Cannot remove owner!")
        return
    
    # Remove from admins
    result = admins_col.delete_one({'user_id': target_uid})
    
    if result.deleted_count > 0:
        # Notify
        try:
            await main_bot.send_message(target_uid, "❌ Your admin access has been revoked.")
        except:
            pass
        
        await event.respond(f"✅ Removed `{target_uid}` from admins!")
    else:
        await event.respond(f"`{target_uid}` is not an admin!")

@main_bot.on(events.NewMessage(pattern=r'^/go(?:@[\w_]+)?(?:\s|$)'))
async def cmd_go(event):
    """User: Start all ads forwarding."""
    uid = event.sender_id
    
    if not await enforce_forcejoin_or_prompt(event):
        return
    
    accounts = get_user_accounts(uid)
    if not accounts:
        await event.respond("No accounts added! Use /start to add accounts.")
        return
    
    # Update all added accounts profile (last name + bio) when starting ads
    try:
        await apply_account_profile_templates(uid)
    except Exception:
        pass

    # Start forwarding for all accounts (with group check)
    user = get_user(uid)
    fwd_mode = user.get('forwarding_mode', 'both')  # Default to 'both' to check all sources
    
    started = 0
    skipped = 0
    
    for acc in accounts:
        acc_id = str(acc['_id'])
        
        if not acc.get('is_forwarding'):
            # Check if account has groups (topics OR auto groups)
            has_groups = False
            
            # Always check both sources regardless of mode
            topic_count = account_topics_col.count_documents({'account_id': acc_id})
            auto_count = account_auto_groups_col.count_documents({'account_id': acc_id})
            
            has_groups = (topic_count > 0) or (auto_count > 0)
            
            if has_groups:
                accounts_col.update_one({'_id': acc['_id']}, {'$set': {'is_forwarding': True}})
                
                if acc['_id'] not in forwarding_tasks or forwarding_tasks[acc['_id']].done():
                    task = asyncio.create_task(run_forwarding_loop(uid, acc['_id']))
                    forwarding_tasks[acc['_id']] = task
                
                started += 1
            else:
                skipped += 1
    
    if started == 0:
        await event.respond(
            "⚠️ No accounts with groups found!\n\n"
            f"Total accounts: {len(accounts)}\n"
            f"Accounts without groups: {skipped}\n\n"
            "Add groups in Dashboard → Topics or enable auto-fetch."
        )
    else:
        msg = f"▶️ Started {started} account(s)!"
        if skipped > 0:
            msg += f"\n\n⏭️ Skipped {skipped} account(s) without groups."
        await event.respond(msg)


@main_bot.on(events.NewMessage(pattern=r'^/run(?:@[\w_]+)?(?:\s|$)'))
async def cmd_run(event):
    """User: Alias for /go."""
    await cmd_go(event)


@main_bot.on(events.NewMessage(pattern=r'^/status(?:@[\w_]+)?(?:\s|$)'))
async def cmd_status(event):
    """User: Show broadcast status + account summary."""
    uid = event.sender_id

    if not await enforce_forcejoin_or_prompt(event):
        return

    user = get_user(uid)
    accounts = get_user_accounts(uid)
    total = len(accounts)
    active = sum(1 for a in accounts if a.get('is_forwarding'))

    mode = user.get('forwarding_mode', 'topics')
    preset = user.get('interval_preset', 'medium')

    text = (
        f"<b>📡 Status</b>\n\n"
        f"<b>Accounts:</b> {active}/{total} active\n"
        f"<b>Mode:</b> <code>{mode}</code>\n"
        f"<b>Intervals:</b> <code>{preset}</code>\n"
    )

    if total == 0:
        text += "\n<i>No accounts added yet. Use /start or /add.</i>"

    await event.respond(text, parse_mode='html')


@main_bot.on(events.NewMessage(pattern=r'^/me(?:@[\w_]+)?(?:\s|$)'))
async def cmd_me(event):
    """User: Show your profile/tier/settings summary."""
    uid = event.sender_id

    if not await enforce_forcejoin_or_prompt(event):
        return

    user = get_user(uid)
    tier = 'Admin' if is_admin(uid) else ('Premium' if is_premium(uid) else 'Free')
    max_accounts = get_user_max_accounts(uid)

    accounts = get_user_accounts(uid)
    total = len(accounts)
    active = sum(1 for a in accounts if a.get('is_forwarding'))

    mode = user.get('forwarding_mode', 'topics')
    preset = user.get('interval_preset', 'medium')

    text = (
        f"<b>👤 Me</b>\n\n"
        f"<b>ID:</b> <code>{uid}</code>\n"
        f"<b>Tier:</b> {tier}\n"
        f"<b>Approved:</b> {('✅' if user.get('approved') else '❌')}\n"
        f"<b>Accounts:</b> {total}/{max_accounts} (active: {active})\n"
        f"<b>Mode:</b> <code>{mode}</code>\n"
        f"<b>Intervals:</b> <code>{preset}</code>\n"
    )

    await event.respond(text, parse_mode='html')


@main_bot.on(events.NewMessage(pattern=r'^/stats(?:@[\w_]+)?(?:\s|$)'))
async def cmd_stats(event):
    """Admin only: Basic bot stats."""
    uid = event.sender_id

    # Admin-only command - don't respond to normal users
    if not is_admin(uid):
        return

    total_users = users_col.count_documents({})
    total_accounts = accounts_col.count_documents({})
    premium_users = users_col.count_documents({'tier': 'premium'})
    active_accounts = accounts_col.count_documents({'is_forwarding': True})

    text = (
        f"<b>📊 Bot Stats</b>\n\n"
        f"<b>Users:</b> {total_users}\n"
        f"<b>Premium Users:</b> {premium_users}\n"
        f"<b>Total Accounts:</b> {total_accounts}\n"
        f"<b>Active Accounts:</b> {active_accounts}\n"
    )

    await event.respond(text, parse_mode='html')


@main_bot.on(events.NewMessage(pattern=r'^/finduser(?:@[\w_]+)?\s+(\d+)$'))
async def cmd_finduser(event):
    """Admin: Lookup a user by ID."""
    uid = event.sender_id
    if not is_admin(uid):
        return

    target = int(event.pattern_match.group(1))
    user = users_col.find_one({'user_id': target})

    if not user:
        await event.respond(f"User <code>{target}</code> not found.", parse_mode='html')
        return

    accounts = list(accounts_col.find({'owner_id': target}))
    total = len(accounts)
    active = sum(1 for a in accounts if a.get('is_forwarding'))

    tier = user.get('tier', 'free')
    max_acc = user.get('max_accounts', FREE_TIER.get('max_accounts', 1))
    approved = user.get('approved', False)

    created_at = user.get('created_at')
    created_str = created_at.strftime('%Y-%m-%d %H:%M') if hasattr(created_at, 'strftime') else str(created_at)

    text = (
        f"<b>🔎 User</b>\n\n"
        f"<b>ID:</b> <code>{target}</code>\n"
        f"<b>Tier:</b> <code>{tier}</code>\n"
        f"<b>Approved:</b> {('✅' if approved else '❌')}\n"
        f"<b>Max Accounts:</b> {max_acc}\n"
        f"<b>Accounts:</b> {active}/{total} active\n"
        f"<b>Created:</b> <code>{created_str}</code>\n"
    )

    await event.respond(text, parse_mode='html')


@main_bot.on(events.NewMessage(pattern=r'^/stop(?:@[\w_]+)?(?:\s|$)'))
async def cmd_stop(event):
    """User: Stop all ads forwarding."""
    uid = event.sender_id
    
    if not await enforce_forcejoin_or_prompt(event):
        return
    
    accounts = get_user_accounts(uid)
    stopped = 0
    
    for acc in accounts:
        if acc.get('is_forwarding'):
            accounts_col.update_one({'_id': acc['_id']}, {'$set': {'is_forwarding': False}})
            stopped += 1
    
    await event.respond(f"⏹️ Stopped {stopped} accounts!")

@main_bot.on(events.NewMessage(pattern=r'^/mystats(?:@[\w_]+)?(?:\s|$)'))
async def cmd_mystats(event):
    """User: Show personal stats."""
    uid = event.sender_id
    
    if not await enforce_forcejoin_or_prompt(event):
        return
    
    user = get_user(uid)
    accounts = get_user_accounts(uid)
    tier = "Premium" if is_premium(uid) else "Free"
    
    total_sent = sum(get_account_stats(str(acc['_id'])).get('total_sent', 0) for acc in accounts)
    total_failed = sum(get_account_stats(str(acc['_id'])).get('total_failed', 0) for acc in accounts)
    active = sum(1 for acc in accounts if acc.get('is_forwarding'))
    
    text = (
        f"📊 **Your Stats**\n\n"
        f"Tier: {tier}\n"
        f"Accounts: {len(accounts)}\n"
        f"Active: {active}\n\n"
        f"Total Sent: {total_sent}\n"
        f"Total Failed: {total_failed}\n"
    )
    
    await event.respond(text)

@main_bot.on(events.NewMessage(pattern=r'^/upgrade(?:@[\w_]+)?(?:\s|$)'))
async def cmd_upgrade(event):
    """User: Show upgrade options."""
    uid = event.sender_id
    
    if not await enforce_forcejoin_or_prompt(event):
        return
    
    # Show plan selection
    plan_msg = (
        "💎 **Choose Your Plan:**\n\n"
        "• Scout - Free starter plan\n"
        "• Grow - Scale your campaigns (₹69)\n"
        "• Prime - Advanced automation (₹199)\n"
        "• Dominion - Enterprise level (₹389)"
    )
    
    if PLAN_IMAGE_URL:
        await main_bot.send_file(uid, PLAN_IMAGE_URL, caption=plan_msg, buttons=plan_select_keyboard(uid))
    else:
        await event.respond(plan_msg, buttons=plan_select_keyboard(uid))

@main_bot.on(events.NewMessage(pattern=r'^/bd(?:@[\w_]+)?$', func=lambda e: e.is_reply))
async def cmd_bd_broadcast(event):
    """Admin: Broadcast by replying to a message with /bd - forwards with sender name, media, buttons"""
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    # Get the replied message
    replied_msg = await event.get_reply_message()
    if not replied_msg:
        await event.respond("Reply to a message with /bd to broadcast it!")
        return
    
    users = get_all_users()
    total = len(users)
    
    # Get sender info
    sender = await replied_msg.get_sender()
    sender_name = getattr(sender, 'first_name', 'Unknown')
    sender_username = getattr(sender, 'username', None)
    sender_display = f"@{sender_username}" if sender_username else sender_name
    
    # Progress message
    progress_msg = await event.respond(f"📢 Broadcasting from {sender_display}...\n0/{total} (0%)")
    
    sent = 0
    failed = 0
    
    for i, u in enumerate(users):
        try:
            # Forward the message directly (preserves media, buttons, formatting)
            await main_bot.forward_messages(
                u['user_id'],
                replied_msg,
                from_peer=event.chat_id
            )
            sent += 1
        except Exception as e:
            failed += 1
            print(f"[BROADCAST] Failed to send to {u['user_id']}: {e}")
        
        # Update progress every 10 users or at end
        if (i + 1) % 10 == 0 or (i + 1) == total:
            percent = int(((i + 1) / total) * 100)
            await progress_msg.edit(
                f"📢 Broadcasting from {sender_display}...\n{i + 1}/{total} ({percent}%)\n\n"
                f"✅ Sent: {sent}\n❌ Failed: {failed}"
            )
        
        # Small delay to avoid flood
        await asyncio.sleep(0.05)
    
    await progress_msg.edit(
        f"✅ <b>Broadcast Complete!</b>\n\n"
        f"<b>From:</b> {sender_display}\n"
        f"<b>Total:</b> {total}\n"
        f"<b>Sent:</b> {sent}\n"
        f"<b>Failed:</b> {failed}",
        parse_mode='html'
    )

@main_bot.on(events.NewMessage(pattern=r'^/broadcast(?:@[\w_]+)?\s+(.+)$', func=lambda e: not e.is_reply))
async def cmd_broadcast(event):
    uid = event.sender_id
    if not is_admin(uid):
        return
    
    msg = event.pattern_match.group(1)
    users = get_all_users()
    
    sent = 0
    failed = 0
    for u in users:
        try:
            await main_bot.send_message(u['user_id'], f"**Announcement**\n\n{msg}")
            sent += 1
        except:
            failed += 1
    
    await event.respond(f"Broadcast complete!\nSent: {sent}\nFailed: {failed}")

@main_bot.on(events.NewMessage(pattern=r'^/add(?:@[\w_]+)?(?:\s|$)'))
async def cmd_add(event):
    uid = event.sender_id

    if not await enforce_forcejoin_or_prompt(event):
        return

    if not is_approved(uid):
        approve_user(uid)
    
    accounts = get_user_accounts(uid)
    max_accounts = get_user_max_accounts(uid)
    
    if len(accounts) >= max_accounts:
        if is_premium(uid):
            await event.respond(f"Account limit reached ({max_accounts}). Contact admin for more.")
        else:
            await event.respond(f"Free tier limit: {max_accounts} account(s).\nUpgrade to Premium for more!")
        return
    
    user_states[uid] = {'action': 'phone'}
    await event.respond("Send phone number with country code:\n\nExample: `+919876543210`")

@main_bot.on(events.NewMessage(pattern=r'^/list(?:@[\w_]+)?(?:\s|$)'))
async def cmd_list(event):
    uid = event.sender_id

    if not await enforce_forcejoin_or_prompt(event):
        return

    if not is_approved(uid):
        approve_user(uid)
    
    accounts = get_user_accounts(uid)
    if not accounts:
        await event.respond("No accounts. Use /add")
        return
    
    tier = "Premium" if is_premium(uid) else "Free"
    max_acc = get_user_max_accounts(uid)
    
    text = f"**Your Accounts** ({tier})\n\n"
    for i, acc in enumerate(accounts, 1):
        status = "Active" if acc.get('is_forwarding') else "Inactive"
        text += f"{status} #{i} - {acc['phone']} ({acc.get('name', 'Unknown')})\n"
    text += f"\nUsing: {len(accounts)}/{max_acc}"
    
    await event.respond(text)

@main_bot.on(events.CallbackQuery)
async def callback(event):
    uid = event.sender_id
    data = event.data.decode()

    # Force-join gate for interactive UI (admin bypass).
    # Allow verify button itself.
    if data != "force_verify":
        if not await enforce_forcejoin_or_prompt(event, edit=True):
            return
    
    try:
        if data == "force_verify":
            # User claims they joined; re-validate.
            if await is_user_passed_forcejoin(uid):
                # Delete the force-join message
                try:
                    await event.delete()
                except:
                    pass
                
                # Show Privacy Policy screen (new flow)
                await main_bot.send_message(
                    uid,
                    MESSAGES['privacy_short'],
                    parse_mode='html',
                    buttons=[
                        [Button.url("📄 View Full Privacy Policy", MESSAGES['privacy_full_link'])],
                        [Button.inline("✅ Accept & Continue", b"accept_privacy")]
                    ]
                )
            else:
                await event.answer("Not joined yet. Please join both Channel and Group.", alert=True)
            return
        
        if data == "accept_privacy":
            # User accepted privacy policy → Show welcome with Kabru Ads Now
            welcome_text = (
                "🚀 Welcome to Kabru Ads Bot!\n\n"
                "Automate your Telegram advertising campaigns across multiple groups.\n\n"
                "<blockquote><b>Plans Available:</b>\n"
                "• Scout (Free)\n"
                "• Grow (₹69)\n"
                "• Prime (₹199)\n"
                "• Dominion (₹389)</blockquote>\n\n"
                "Click <b>Kabru Ads Now</b> to choose your plan!"
            )
            welcome_image = MESSAGES.get('welcome_image', '')
            if welcome_image:
                await event.delete()
                await main_bot.send_file(
                    uid,
                    welcome_image,
                    caption=welcome_text,
                    parse_mode='html',
                    buttons=[[Button.inline("🚀 Kabru Ads Now", b"adsye_now")]]
                )
            else:
                await event.edit(
                    welcome_text,
                    parse_mode='html',
                    buttons=[[Button.inline("🚀 Kabru Ads Now", b"adsye_now")]]
                )
            return


        if data.startswith("plan_"):
            plan_name = data.replace("plan_", "")
            
            plan = PLANS.get(plan_name)
            if not plan:
                await event.answer("Invalid plan!", alert=True)
                return
            
            # Show plan details with tagline + Buy Now button
            detail_text = (
                f"<b>{plan['emoji']} {plan['name']} Plan</b>\n\n"
                f"<i>{plan['tagline']}</i>\n\n"
                f"<blockquote><b>Plan Features:</b>\n\n"
                f"💼 <b>Accounts:</b> {plan['max_accounts']}\n"
                f"📂 <b>Topics:</b> {plan['max_topics']}\n"
                f"👥 <b>Groups per Topic:</b> {plan['max_groups_per_topic']}\n\n"
                f"⏱️ <b>Delays:</b>\n"
                f"  • Message: {plan['msg_delay']}s\n"
                f"  • Group: {plan['group_delay']}s\n"
                f"  • Round: {plan['round_delay']}s\n\n"
                f"✨ <b>Features:</b>\n"
                f"  • Auto Reply: {'Yes' if plan['auto_reply_enabled'] else 'No'}\n"
                f"  • Logs: {'Yes' if plan['logs_enabled'] else 'No'}\n"
                f"{'  • 🔄 Smart Rotation: Yes\n' if plan_name != 'scout' else ''}"
                f"{'  • 👥 Auto Group Join: Yes' if plan_name != 'scout' else ''}</blockquote>\n\n"
            )
            
            if plan_name == "scout":
                # Free plan - Show "Activate Free" or "Active" button
                user = get_user(uid)
                is_scout_active = user.get('approved') and user.get('tier') == 'free'
                
                detail_text += f"<b>Price: FREE</b>"
                
                if is_scout_active:
                    buttons = [
                        [Button.inline("✓ Active Plan", b"enter_dashboard")],
                        [Button.inline("← Back to Plans", b"back_plans")]
                    ]
                else:
                    buttons = [
                        [Button.inline("✅ Activate Free Plan", b"activate_scout")],
                        [Button.inline("← Back to Plans", b"back_plans")]
                    ]
            else:
                # Paid plans - Check if user already has this plan
                user = get_user(uid)
                user_plan_name = user.get('plan_name', '').lower()
                is_active_plan = user_plan_name == plan_name
                
                detail_text += f"<b>Price: {plan['price_display']}</b>"
                
                if is_active_plan:
                    # User already has this plan - show Active
                    buttons = [
                        [Button.inline("✓ Active Plan", b"enter_dashboard")],
                        [Button.inline("← Back to Plans", b"back_plans")]
                    ]
                else:
                    # Show Buy Now button
                    buttons = [
                        [Button.inline(f"💳 Buy Now - {plan['price_display']}", f"buy_{plan_name}")],
                        [Button.inline("← Back to Plans", b"back_plans")]
                    ]
            
            await event.edit(detail_text, parse_mode='html', buttons=buttons)
            return
        
        if data == "activate_scout":
            # Activate Scout (free) plan
            approve_user(uid)
            await event.answer("Scout plan activated!", alert=True)
            
            # Redirect to dashboard
            await event.edit(render_dashboard_text(uid), parse_mode='html', buttons=main_dashboard_keyboard(uid))
            return
        
        # ===================== Manual UPI Payment Callbacks =====================
        
        if data.startswith("paydone_"):
            # User clicked "Payment Done" - now ask for screenshot
            parts = data.split("_", 1)
            if len(parts) < 2:
                await event.answer("Invalid payment request", alert=True)
                return
            
            request_id = parts[1]
            pay_req = pending_upi_payments.get(request_id)
            if not pay_req:
                await event.answer("Payment request expired or not found", alert=True)
                return
            
            # Set user state to awaiting screenshot
            pay_req['status'] = 'awaiting_screenshot'
            user_states[uid] = {'state': 'awaiting_payment_screenshot', 'request_id': request_id}
            
            await event.edit(
                "<b>📸 Upload Payment Screenshot</b>\n\n"
                f"<b>Plan:</b> {pay_req['plan_name']}\n"
                f"<b>Amount:</b> ₹{pay_req['price']}\n\n"
                "Please send the payment screenshot now.\n\n"
                "<i>Tap Back to cancel.</i>",
                parse_mode='html',
                buttons=[[Button.inline("🔙 Back", f"payback_{request_id}".encode())]]
            )
            return
        
        elif data.startswith("payback_"):
            # User clicked Back during payment - restore start image
            parts = data.split("_", 1)
            if len(parts) < 2:
                request_id = None
            else:
                request_id = parts[1]
                if request_id in pending_upi_payments:
                    del pending_upi_payments[request_id]
            
            # Clear user state
            if uid in user_states:
                del user_states[uid]
            
            # Show start screen with start image
            welcome_img = MESSAGES.get('welcome_image')
            welcome_txt = (
                "<b>🏠 Welcome Back!</b>\n\n"
                "Payment cancelled. Use the menu below to continue."
            )
            buttons = main_dashboard_keyboard(uid)
            
            try:
                await event.edit(welcome_txt, parse_mode='html', buttons=buttons, file=welcome_img)
            except Exception:
                await event.edit(welcome_txt, parse_mode='html', buttons=buttons)
            return
        
        elif data.startswith("payapprove_"):
            # Admin approves payment
            parts = data.split("_", 1)
            if len(parts) < 2:
                await event.answer("Invalid approve request", alert=True)
                return
            
            request_id = parts[1]
            pay_req = pending_upi_payments.get(request_id)
            if not pay_req:
                await event.answer("Payment request not found or already processed", alert=True)
                return
            
            plan_key = pay_req['plan_key']
            plan = PLANS.get(plan_key)
            if not plan:
                await event.answer("Plan not found", alert=True)
                return
            
            target_uid = pay_req['user_id']
            
            # Grant premium for 30 days
            max_accounts = plan.get('max_accounts', 1)
            set_user_premium(target_uid, max_accounts, plan_name=plan.get('name', plan_key))
            
            # Update payment status
            pay_req['status'] = 'approved'
            
            # Notify user
            try:
                await main_bot.send_message(
                    target_uid,
                    f"<b>✅ Payment Approved</b>\n\n"
                    f"<b>Plan:</b> {plan['emoji']} {plan['name']}\n"
                    f"<b>Duration:</b> 30 days\n\n"
                    f"Your premium features are now active! 🎉",
                    parse_mode='html'
                )
            except Exception as e:
                print(f"[PAYMENT] Failed to notify user {target_uid}: {e}")
            
            # Edit admin message
            try:
                msg = event.query.message if hasattr(event, 'query') else None
                if msg:
                    await event.edit(
                        msg.text + "\n\n<b>✅ APPROVED by admin</b>",
                        parse_mode='html',
                        buttons=None
                    )
            except Exception as e:
                print(f"[PAYMENT] Failed to edit admin message: {e}")
            
            await event.answer("Payment approved and user notified!", alert=False)
            
            # Clean up
            del pending_upi_payments[request_id]
            if msg and msg.id in admin_payment_message_map:
                del admin_payment_message_map[msg.id]
            return
        
        elif data.startswith("payreject_"):
            # Admin rejects payment
            parts = data.split("_", 1)
            if len(parts) < 2:
                await event.answer("Invalid reject request", alert=True)
                return
            
            request_id = parts[1]
            pay_req = pending_upi_payments.get(request_id)
            if not pay_req:
                await event.answer("Payment request not found or already processed", alert=True)
                return
            
            target_uid = pay_req['user_id']
            pay_req['status'] = 'rejected'
            
            # Notify user
            try:
                await main_bot.send_message(
                    target_uid,
                    f"<b>❌ Payment Rejected</b>\n\n"
                    f"Your payment screenshot was not verified.\n\n"
                    f"Please contact support if you believe this is an error.",
                    parse_mode='html'
                )
            except Exception as e:
                print(f"[PAYMENT] Failed to notify user {target_uid}: {e}")
            
            # Edit admin message
            try:
                msg = event.query.message if hasattr(event, 'query') else None
                if msg:
                    await event.edit(
                        msg.text + "\n\n<b>❌ REJECTED by admin</b>",
                        parse_mode='html',
                        buttons=None
                    )
            except Exception as e:
                print(f"[PAYMENT] Failed to edit admin message: {e}")
            
            await event.answer("Payment rejected and user notified.", alert=False)
            
            # Clean up
            del pending_upi_payments[request_id]
            if msg and msg.id in admin_payment_message_map:
                del admin_payment_message_map[msg.id]
            return
        
        if data.startswith("buy_"):
            # Buy paid plan - show UPI QR directly
            plan_key = data.replace("buy_", "")
            plan = PLANS.get(plan_key)
            if not plan:
                await event.answer("Plan not found", alert=True)
                return
            
            # Create payment request
            request_id = _new_payment_request_id(uid, plan_key)
            sender = await event.get_sender()
            username = sender.username if hasattr(sender, 'username') else None
            
            pending_upi_payments[request_id] = {
                'user_id': uid,
                'username': username,
                'plan_key': plan_key,
                'plan_name': plan['name'],
                'price': plan.get('price', 0),
                'created_at': datetime.now(),
                'status': 'awaiting_payment'
            }
            
            # Show UPI QR
            qr_url = UPI_PAYMENT.get('qr_image_url', '')
            caption = _upi_payment_caption(plan, plan_key)
            
            await event.edit(
                caption,
                parse_mode='html',
                file=qr_url,
                buttons=[
                    [Button.inline("✅ Payment Done", f"paydone_{request_id}".encode())],
                    [Button.inline("🔙 Back", f"payback_{request_id}".encode())]
                ]
            )
            return

        if data == "adsye_now":
            # Acknowledge immediately to avoid Telegram's loading animation
            try:
                await event.answer(cache_time=0)
            except Exception:
                pass

            # NEW FLOW: Show plan selection (not account add)
            plan_msg = render_plan_select_text()
            
            if PLAN_IMAGE_URL:
                try:
                    await event.delete()
                except:
                    pass
                await main_bot.send_file(
                    uid,
                    PLAN_IMAGE_URL,
                    caption=plan_msg,
                    parse_mode='html',
                    buttons=plan_select_keyboard(uid)
                )
            else:
                await event.edit(plan_msg, parse_mode='html', buttons=plan_select_keyboard(uid))
            return

        if data.startswith("admin_"):
            # Admin panel callbacks
            if not is_admin(uid):
                return
            
            if data == "admin_users":
                # System stats (CPU/RAM/Disk) + platform stats
                cpu_pct = psutil.cpu_percent(interval=0.3)
                mem = psutil.virtual_memory()
                root_path = os.path.abspath(os.sep)
                disk = psutil.disk_usage(root_path)

                total_users = users_col.count_documents({})
                premium_users = users_col.count_documents({'tier': 'premium'})
                today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                new_today = users_col.count_documents({'created_at': {'$gte': today_start}}) if users_col.find_one({}, {'created_at': 1}) else 0
                banned_users = 0  # Placeholder for banned users feature
                
                # Premium by plan (counts)
                grow_count = users_col.count_documents({'tier': 'premium', 'plan_name': {'$regex': '^grow$', '$options': 'i'}})
                prime_count = users_col.count_documents({'tier': 'premium', 'plan_name': {'$regex': '^prime$', '$options': 'i'}})
                dominion_count = users_col.count_documents({'tier': 'premium', 'plan_name': {'$regex': '^dominion$', '$options': 'i'}})
                
                # Accounts
                total_accounts = accounts_col.count_documents({})
                active_broadcasts = accounts_col.count_documents({'is_forwarding': True})
                
                # Messaging stats
                total_ads_sent = sum(stat.get('total_sent', 0) for stat in account_stats_col.find({}, {'total_sent': 1}))
                # Auto replies counter (stored in db, incremented when auto-reply is sent)
                auto_replies = sum(stat.get('auto_replies', 0) for stat in account_stats_col.find({}, {'auto_replies': 1}))
                target_groups = account_topics_col.count_documents({}) + account_auto_groups_col.count_documents({})
                
                # Topics
                total_topics = account_topics_col.count_documents({})
                active_topics = len(set(t['topic'] for t in account_topics_col.find({}, {'topic': 1})))
                failed_topics = account_failed_groups_col.count_documents({})
                
                text = (
                    f"<b>🖥️ SYSTEM STATS</b>\n\n"
                    f"<b>CPU:</b> <code>{cpu_pct:.0f}%</code>\n"
                    f"<b>RAM:</b> <code>{mem.percent:.0f}%</code> <i>({mem.used//(1024**3)}GB/{mem.total//(1024**3)}GB)</i>\n"
                    f"<b>DISK:</b> <code>{disk.percent:.0f}%</code> <i>({disk.used//(1024**3)}GB/{disk.total//(1024**3)}GB)</i>\n\n"
                    f"<b>👥 USERS:</b>\n"
                    f"<code>├ Total: {total_users}\n"
                    f"├ Subscribers: {premium_users}\n"
                    f"├ New Today: {new_today}\n"
                    f"└ Banned: {banned_users}</code>\n\n"
                    f"<b>✦ PREMIUM BY PLAN:</b>\n"
                    f"<code>├ Grow: {grow_count}\n"
                    f"├ Prime: {prime_count}\n"
                    f"└ Dominion: {dominion_count}</code>\n\n"
                    f"<b>📱 ACCOUNTS:</b>\n"
                    f"<code>├ Total: {total_accounts}\n"
                    f"└ Active Broadcasts: {active_broadcasts}</code>\n\n"
                    f"<b>💬 MESSAGING:</b>\n"
                    f"<code>├ Total Ads Sent: {total_ads_sent}\n"
                    f"├ Auto-Replies: {auto_replies}\n"
                    f"└ Target Groups: {target_groups}</code>\n\n"
                    f"<b>📂 TOPICS:</b>\n"
                    f"<code>├ Total: {total_topics}\n"
                    f"├ Active: {active_topics}\n"
                    f"└ Failed: {failed_topics}</code>"
                )
                
                await event.edit(text, parse_mode='html', buttons=[[Button.inline("← Back", b"back_admin")]])
                return
            
            if data == "admin_admins":
                admins = list(admins_col.find())
                text = f"**Admins List**\n\nOwner: `{CONFIG['owner_id']}`\n\n"
                for a in admins:
                    text += f"`{a['user_id']}`\n"
                
                await event.edit(text, buttons=[[Button.inline("🏠 Back", b"back_admin")]])
                return
            
            if data == "admin_stats":
                # psutil is imported at module level
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                text = (
                    f"**System Stats**\n\n"
                    f"CPU: {cpu}%\n"
                    f"RAM: {ram.percent}% ({ram.used // (1024**3)}GB / {ram.total // (1024**3)}GB)\n"
                    f"Disk: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)\n"
                )
                
                await event.edit(text, buttons=[[Button.inline("🏠 Back", b"back_admin")]])
                return
            
            if data == "admin_controls":
                text = "**Bot Controls**\n\nUse commands:\n/ping - System stats\n/reboot - Restart bot"
                await event.edit(text, buttons=[[Button.inline("🏠 Back", b"back_admin")]])
                return
            
            if data == "back_admin":
                # Recreate admin panel
                total_users = users_col.count_documents({})
                premium_users = users_col.count_documents({'tier': 'premium'})
                total_accounts = accounts_col.count_documents({})
                active_accounts = accounts_col.count_documents({'is_forwarding': True})
                total_admins = admins_col.count_documents({}) + 1
                
                text = (
                    "<b>Admin Panel</b>\n\n"
                    "<b>Bot Statistics</b>\n"
                    f"Total Users: <code>{total_users}</code>\n"
                    f"Premium Users: <code>{premium_users}</code>\n"
                    f"Total Accounts: <code>{total_accounts}</code>\n"
                    f"Active Forwarding: <code>{active_accounts}</code>\n"
                    f"Total Admins: <code>{total_admins}</code>\n\n"
                    "<i>Use commands or buttons below:</i>"
                )

                buttons = [
                    [Button.inline("👥 View Users", b"admin_users"), Button.inline("👑 View Admins", b"admin_admins")],
                    [Button.inline("📊 Full Stats", b"admin_stats"), Button.inline("🔧 Bot Controls", b"admin_controls")],
                    [Button.inline("🏠 Back", b"back_start")]
                ]

                await event.edit(text, parse_mode='html', buttons=buttons)
                return

        if data.startswith("addprm_"):
            # Admin granting premium plan
            if not is_admin(uid):
                return
            
            state = user_states.get(uid, {})
            target_uid = state.get('target_uid')
            
            if not target_uid:
                await event.answer("Session expired!", alert=True)
                return
            
            if data == "addprm_cancel":
                del user_states[uid]
                await event.edit("Cancelled.")
                return
            
            # Extract plan name
            plan_name = data.replace("addprm_", "")
            plan = PLANS.get(plan_name)
            
            if not plan:
                await event.answer("Invalid plan!", alert=True)
                return
            
            # Grant premium with plan name
            plan_name = plan_id.replace('plan_', '').capitalize()
            set_user_premium(target_uid, plan['max_accounts'], plan_name)
            
            # Notify target user
            try:
                await main_bot.send_message(
                    target_uid,
                    f"**Premium Activated**\n\n"
                    f"Plan: {plan['name']}\n"
                    f"Accounts: {plan['max_accounts']}\n\n"
                    f"Your premium plan has been activated by admin!\n"
                    f"Enjoy all features."
                )
            except:
                pass
            
            # Confirm to admin
            del user_states[uid]
            await event.edit(
                f"**Premium Granted**\n\n"
                f"User: `{target_uid}`\n"
                f"Plan: {plan['name']}\n"
                f"Accounts: {plan['max_accounts']}\n\n"
                f"User has been notified."
            )
            return

        if data == "noop":
            await event.answer("Account limit reached!")
            return
        
        if data == "back_plans":
            # Return to plan selection screen
            plan_msg = (
                "<b>💎 Choose Your Plan</b>\n\n"
                "<blockquote>Select a plan that fits your advertising needs.\n"
                "You can upgrade anytime.</blockquote>"
            )

            if PLAN_IMAGE_URL:
                # Edit caption/text only (media edit is tricky); just edit message text
                await event.edit(plan_msg, parse_mode='html', buttons=plan_select_keyboard(uid))
            else:
                await event.edit(plan_msg, parse_mode='html', buttons=plan_select_keyboard(uid))
            return

        if data == "back_start":
            # If force-join is enabled and user isn't joined, show lock screen
            if not await enforce_forcejoin_or_prompt(event, edit=True):
                return

            # Check if user has accounts
            accounts = get_user_accounts(uid)
            
            if len(accounts) > 0:
                # User has accounts, show plan selection
                plan_msg = (
                    "**💎 Choose Your Plan to Continue:**\n\n"
                    "• Scout - Free starter plan\n"
                    "• Grow - Scale your campaigns (₹69)\n"
                    "• Prime - Advanced automation (₹199)\n"
                    "• Dominion - Enterprise level (₹389)"
                )
                
                if PLAN_IMAGE_URL:
                    try:
                        await event.delete()
                    except:
                        pass
                    await main_bot.send_file(uid, PLAN_IMAGE_URL, caption=plan_msg, buttons=plan_select_keyboard(uid))
                else:
                    await event.edit(plan_msg, parse_mode='html', buttons=plan_select_keyboard(uid))
            else:
                # No accounts, show welcome screen
                await event.edit(render_welcome_text(), parse_mode='html', buttons=new_welcome_keyboard())
            return
        
        if data == "enter_dashboard":
            # Force-join gate (extra safety)
            if not await enforce_forcejoin_or_prompt(event, edit=True):
                return

            if not is_approved(uid):
                approve_user(uid)

            # Update account profiles when dashboard loads
            try:
                await apply_account_profile_templates(uid)
            except Exception:
                pass

            text = render_dashboard_text(uid)
            
            buttons = main_dashboard_keyboard(uid)
            # Admin button removed (already in main_dashboard_keyboard)
            
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data == "menu_account":
            accounts = get_user_accounts(uid)
            max_acc = get_user_max_accounts(uid)
            text = (
                f"<b>👤 Account Management</b>\n\n"
                f"<b>Accounts:</b> <code>{len(accounts)}/{max_acc}</code>\n\n"
                f"<i>Select an account below or add a new one.</i>"
            )
            await event.edit(text, parse_mode='html', buttons=account_list_keyboard(uid))
            return
        
        if data.startswith("accpage_"):
            page = int(data.split("_")[1])
            accounts = get_user_accounts(uid)
            max_acc = get_user_max_accounts(uid)
            text = (
                f"<b>👤 Account Management</b>\n\n"
                f"<b>Accounts:</b> <code>{len(accounts)}/{max_acc}</code>\n\n"
                f"<i>Page:</i> <code>{page+1}</code>"
            )
            await event.edit(text, parse_mode='html', buttons=account_list_keyboard(uid, page))
            return
        
        if data == "add_account":
            accounts = get_user_accounts(uid)
            max_accounts = get_user_max_accounts(uid)
            if len(accounts) >= max_accounts:
                await event.answer(f"Account limit reached ({max_accounts})!", alert=True)
                return
            user_states[uid] = {'action': 'phone'}
            await event.edit("**Add Account**\n\nSend phone number with country code:\n\nExample: `+919876543210`", buttons=[[Button.inline("Cancel", b"menu_account")]])
            return
        
        if data == "delete_account_menu":
            accounts = get_user_accounts(uid)
            if not accounts:
                await event.answer("No accounts to delete!", alert=True)
                return
            await event.edit("**Delete Account**\n\nSelect account to delete:", buttons=delete_account_list_keyboard(uid))
            return
        
        if data.startswith("confirm_del_"):
            acc_id = data.replace("confirm_del_", "")
            from bson.objectid import ObjectId
            try:
                acc = accounts_col.find_one({'_id': ObjectId(acc_id), 'user_id': uid})
            except:
                acc = accounts_col.find_one({'_id': acc_id, 'user_id': uid})
            if acc:
                phone = acc['phone']
                await event.edit(
                    f"**Confirm Delete**\n\nAre you sure you want to delete account:\n`{phone}`?",
                    buttons=[
                        [Button.inline("Yes, Delete", f"final_del_{acc_id}"), Button.inline("No, Cancel", b"delete_account_menu")]
                    ]
                )
            return
        
        if data.startswith("final_del_"):
            acc_id = data.replace("final_del_", "")
            from bson.objectid import ObjectId
            try:
                acc = accounts_col.find_one({'_id': ObjectId(acc_id), 'user_id': uid})
            except:
                acc = accounts_col.find_one({'_id': acc_id, 'user_id': uid})
            if acc:
                real_id = acc['_id']
                if real_id in forwarding_tasks:
                    forwarding_tasks[real_id].cancel()
                    del forwarding_tasks[real_id]
                accounts_col.delete_one({'_id': real_id})
                account_topics_col.delete_many({'account_id': real_id})
                account_settings_col.delete_many({'account_id': real_id})
                account_auto_groups_col.delete_many({'account_id': real_id})
                await event.answer("Account deleted!", alert=True)
            await event.edit(
                "<b>👤 Account Management</b>",
                parse_mode='html',
                buttons=account_list_keyboard(uid)
            )
            return
        
        if data == "menu_analytics":
            accounts = get_user_accounts(uid)
            total_sent = 0
            total_failed = 0
            total_groups = 0
            total_auto_replies = 0
            
            for acc in accounts:
                # Convert ObjectId to string for stats lookup
                account_id = str(acc['_id'])
                stats = account_stats_col.find_one({'account_id': account_id})
                if stats:
                    total_sent += stats.get('total_sent', 0)
                    total_failed += stats.get('total_failed', 0)
                    total_auto_replies += stats.get('auto_replies', 0)
                groups = account_auto_groups_col.count_documents({'account_id': account_id})
                total_groups += groups
            
            active = sum(1 for acc in accounts if acc.get('is_forwarding'))
            
            success_rate = 0.0
            if (total_sent + total_failed) > 0:
                success_rate = (total_sent / (total_sent + total_failed)) * 100

            text = (
                "<b>📈 Analytics</b>\n\n"
                f"<b>Total Accounts:</b> <code>{len(accounts)}</code>\n"
                f"<b>Active Accounts:</b> <code>{active}</code>\n"
                f"<b>Total Groups:</b> <code>{total_groups}</code>\n\n"
                f"<b>Messages Sent:</b> <code>{total_sent}</code>\n"
                f"<b>Messages Failed:</b> <code>{total_failed}</code>\n"
                f"<b>Success Rate:</b> <code>{success_rate:.1f}%</code>\n"
                f"<b>Auto Replies:</b> <code>{total_auto_replies}</code>"
            )

            await event.edit(text, parse_mode='html', buttons=[[Button.inline("← Back", b"enter_dashboard")]])
            return
        
        if data == "menu_interval":
            user = get_user(uid)
            current = user.get('interval_preset', 'medium')
            
            if current == 'custom' and user.get('custom_interval'):
                custom = user['custom_interval']
                text = (
                    "⏱️ Interval Settings\n\n"
                    "Current: Custom\n\n"
                    f"Group Delay: {custom['group_delay']}s\n"
                    f"Message Delay: {custom['msg_delay']}s\n"
                    f"Round Delay: {custom['round_delay']}s"
                )
            else:
                preset = INTERVAL_PRESETS.get(current, INTERVAL_PRESETS['medium'])
                text = (
                    "⏱️ Interval Settings\n\n"
                    f"Current: {preset['name']}\n\n"
                    f"Group Delay: {preset['group_delay']}s\n"
                    f"Message Delay: {preset['msg_delay']}s\n"
                    f"Round Delay: {preset['round_delay']}s"
                )
            
            await event.edit(text, buttons=interval_menu_keyboard(uid))
            return
        
        if data.startswith("interval_") and not data == "interval_upgrade" and not data == "interval_custom":
            preset_key = data.replace("interval_", "")
            if preset_key in INTERVAL_PRESETS:
                users_col.update_one({'user_id': uid}, {'$set': {'interval_preset': preset_key}})
                preset = INTERVAL_PRESETS[preset_key]
                await event.answer(f"Interval set to: {preset['name']}", alert=True)
                
                text = (
                    "⏱️ Interval Settings\n\n"
                    f"Current: {preset['name']}\n\n"
                    f"Group Delay: {preset['group_delay']}s\n"
                    f"Message Delay: {preset['msg_delay']}s\n"
                    f"Round Delay: {preset['round_delay']}s"
                )
                await event.edit(text, buttons=interval_menu_keyboard(uid))
            return
        
        if data == "interval_upgrade":
            owner_id = CONFIG['owner_id']
            text = (
                "<b>⏱️ Custom Interval</b>\n\n"
                "<blockquote>This feature is not available for Free tier.</blockquote>\n\n"
                "<i>Upgrade to Premium to set custom intervals.</i>"
            )
            await event.edit(text, parse_mode='html', buttons=[
                [Button.inline("Upgrade to Premium", b"go_premium")],
                [Button.inline("Back", b"menu_interval")]
            ])
            return
        
        if data == "interval_custom":
            if not is_premium(uid):
                await event.answer("Premium only!", alert=True)
                return
            user_states[uid] = {'action': 'custom_interval', 'step': 'group_delay'}
            await event.edit(
                "⏱️ Custom Interval\n\nEnter group delay in seconds (30-300):",
                buttons=[[Button.inline("← Back", b"menu_interval")]]
            )
            return
        
        if data == "menu_topics":
            accounts = get_user_accounts(uid)
            if not accounts:
                await event.answer("Add an account first!", alert=True)
                return
            
            tier_settings = get_user_tier_settings(uid)
            max_topics = tier_settings.get('max_topics', 3)
            
            text = (
                "<b>🏷️ Topics</b>\n\n"
                "<blockquote>Select a topic to add group links.</blockquote>\n\n"
                f"<b>Available topics:</b> <code>{max_topics}/{len(TOPICS)}</code>"
            )
            if not is_premium(uid):
                text += "\n\n<i>Upgrade to Premium for all topics.</i>"
            
            buttons = []
            for i, topic in enumerate(TOPICS[:max_topics]):
                count = 0
                for acc in accounts:
                    count += account_topics_col.count_documents({'account_id': acc['_id'], 'topic': topic})
                buttons.append([Button.inline(f"{topic.title()} ({count} groups)", f"topic_select_{topic}")])
            
            if not is_premium(uid) and len(TOPICS) > max_topics:
                buttons.append([Button.inline("Unlock More Topics", b"go_premium")])
            
            buttons.append([Button.inline("Back", b"enter_dashboard")])
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("topic_select_"):
            topic = data.replace("topic_select_", "")
            accounts = get_user_accounts(uid)
            
            tier_settings = get_user_tier_settings(uid)
            max_groups = tier_settings.get('max_groups_per_topic', 10)
            
            if len(accounts) == 1:
                acc = accounts[0]
                groups = list(account_topics_col.find({'account_id': acc['_id'], 'topic': topic}))
                
                text = (
                    f"<b>{_h(topic.title())}</b>\n\n"
                    f"<b>Groups:</b> <code>{len(groups)}/{max_groups}</code>\n\n"
                    "<b>Send topic link to add:</b>\n"
                    "<code>https://t.me/groupname/5</code>"
                )
                buttons = [[Button.inline("View Groups", f"view_topic_groups_{topic}_{acc['_id']}")]] if groups else []
                buttons.append([Button.inline("Back", b"menu_topics")])
                msg = await event.edit(text, parse_mode='html', buttons=buttons)
                user_states[uid] = {'action': 'add_topic_link', 'topic': topic, 'account_id': acc['_id'], 'last_msg_id': msg.id if hasattr(msg, 'id') else event.message_id}
            else:
                text = f"<b>{_h(topic.title())}</b>\n\n<i>Select account to add groups:</i>"
                buttons = []
                for acc in accounts:
                    phone = acc['phone'][-4:]
                    name = acc.get('name', 'Unknown')[:12]
                    count = account_topics_col.count_documents({'account_id': acc['_id'], 'topic': topic})
                    buttons.append([Button.inline(f"{phone} - {name} ({count})", f"topic_acc_{topic}_{acc['_id']}")])
                buttons.append([Button.inline("Back", b"menu_topics")])
                await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("topic_acc_"):
            parts = data.replace("topic_acc_", "").split("_", 1)
            topic = parts[0]
            acc_id = parts[1] if len(parts) > 1 else ""
            
            tier_settings = get_user_tier_settings(uid)
            max_groups = tier_settings.get('max_groups_per_topic', 10)
            groups = list(account_topics_col.find({'account_id': acc_id, 'topic': topic}))
            
            text = (
                f"<b>🏷️ {topic.title()}</b>\n\n"
                f"<b>Groups:</b> <code>{len(groups)}/{max_groups}</code>\n\n"
                "<i>Send a topic link to add.</i>\n"
                "<code>Example: https://t.me/groupname/5</code>"
            )
            buttons = [[Button.inline("👁️ View Groups", f"view_topic_groups_{topic}_{acc_id}")]] if groups else []
            buttons.append([Button.inline("← Back", f"topic_select_{topic}")])
            msg = await event.edit(text, parse_mode='html', buttons=buttons)
            user_states[uid] = {'action': 'add_topic_link', 'topic': topic, 'account_id': acc_id, 'last_msg_id': msg.id if hasattr(msg, 'id') else event.message_id}
            return
        
        if data.startswith("view_topic_groups_"):
            parts = data.replace("view_topic_groups_", "").split("_", 1)
            topic = parts[0]
            acc_id = parts[1] if len(parts) > 1 else ""
            
            groups = list(account_topics_col.find({'account_id': acc_id, 'topic': topic}))
            total = len(groups)
            display_limit = 5
            
            text = f"<b>🏷️ {topic.title()} Groups</b> <code>({total} total)</code>\n\n"
            for i, g in enumerate(groups[:display_limit]):
                title = g.get('title', g.get('url', 'Unknown'))[:25]
                text += f"{i+1}. {title}\n"
            
            if total > display_limit:
                text += f"\n...and {total - display_limit} more groups"
            
            buttons = [
                [Button.inline("Clear All", f"clear_topic_{topic}_{acc_id}")],
                [Button.inline("Back", f"topic_select_{topic}")]
            ]
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("clear_topic_"):
            parts = data.replace("clear_topic_", "").split("_", 1)
            topic = parts[0]
            acc_id = parts[1] if len(parts) > 1 else ""
            
            account_topics_col.delete_many({'account_id': acc_id, 'topic': topic})
            await event.answer(f"Cleared all {topic} groups!", alert=True)
            await event.edit(
                f"<b>🏷️ {topic.title()}</b>\n\n<b>Groups:</b> <code>0</code>\n\n<i>Send a group link to add.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back", b"menu_topics")]]
            )
            return
        
        if data == "menu_settings":
            text = "<b>⚙️ Settings</b>\n\n<i>Configure bot features and preferences.</i>"
            await event.edit(text, parse_mode='html', buttons=settings_menu_keyboard(uid))
            return
        if data == "menu_autoreply":
            tier = "Premium" if is_premium(uid) else "Free"
            text = f"<b>💬 Auto Reply</b>\n\n<b>Tier:</b> <code>{tier}</code>\n\n"
            
            if is_premium(uid):
                user = get_user(uid)
                enabled = user.get('autoreply_enabled', True)
                
                # Check if user has set a custom message
                accounts = get_user_accounts(uid)
                has_custom = False
                if accounts:
                    for acc in accounts:
                        settings_doc = account_settings_col.find_one({'account_id': str(acc['_id'])})
                        if settings_doc and 'auto_reply' in settings_doc and settings_doc.get('auto_reply'):
                            has_custom = True
                            break
                
                text += f"<b>Status:</b> <code>{'ON' if enabled else 'OFF'}</code>\n"
                text += f"<b>Custom Reply:</b> {'✅' if has_custom else '❌'} <code>{'Set' if has_custom else 'Not Set'}</code>"
            else:
                text += "🔒 <b>Auto-reply is a premium feature.</b>\n\n"
                text += "Upgrade to premium to set custom auto-reply messages!"
            
            await event.edit(text, parse_mode='html', buttons=autoreply_menu_keyboard(uid))
            return
        
        if data == "autoreply_view":
            if not is_premium(uid):
                await event.answer("Premium only!", alert=True)
                return
            
            # Get custom message from account settings
            accounts = get_user_accounts(uid)
            reply = None
            if accounts:
                for acc in accounts:
                    settings_doc = account_settings_col.find_one({'account_id': str(acc['_id'])})
                    if settings_doc and 'auto_reply' in settings_doc:
                        reply = settings_doc.get('auto_reply')
                        break
            
            if reply:
                text = f"<b>💬 Current Auto Reply</b>\n\n<blockquote>{_h(reply)}</blockquote>"
            else:
                text = "<b>💬 Current Auto Reply</b>\n\n<i>No custom message set yet.</i>"
            
            await event.edit(text, parse_mode='html', buttons=[[Button.inline("← Back", b"menu_autoreply")]])
            return

        if data == "autoreply_toggle":
            if not is_premium(uid):
                await event.answer("Premium feature only", alert=True)
                return

            # Flip the flag and refresh menu
            user = get_user(uid)
            enabled = user.get('autoreply_enabled', True)
            new_value = not enabled
            users_col.update_one({'user_id': int(uid)}, {'$set': {'autoreply_enabled': new_value}})

            try:
                await event.answer(f"Auto Reply {'enabled' if new_value else 'disabled'}", alert=False)
            except Exception:
                pass

            # Re-render menu
            tier = "Premium"
            user = get_user(uid)
            text = f"<b>💬 Auto Reply</b>\n\n<b>Tier:</b> <code>{tier}</code>\n\n"
            enabled = user.get('autoreply_enabled', True)
            
            # Check if user has set a custom message
            accounts = get_user_accounts(uid)
            has_custom = False
            if accounts:
                for acc in accounts:
                    settings_doc = account_settings_col.find_one({'account_id': str(acc['_id'])})
                    if settings_doc and 'auto_reply' in settings_doc and settings_doc.get('auto_reply'):
                        has_custom = True
                        break
            
            text += f"<b>Status:</b> <code>{'ON' if enabled else 'OFF'}</code>\n"
            text += f"<b>Custom Reply:</b> {'✅' if has_custom else '❌'} <code>{'Set' if has_custom else 'Not Set'}</code>"
            await event.edit(text, parse_mode='html', buttons=autoreply_menu_keyboard(uid))
            return
        
        if data == "autoreply_custom":
            if not is_premium(uid):
                await event.answer("Premium only!", alert=True)
                return
            user_states[uid] = {'action': 'custom_autoreply'}
            await event.edit(
                "<b>💬 Set Custom Reply</b>\n\nSend your custom auto-reply message:",
                parse_mode='html',
                buttons=[[Button.inline("← Back", b"menu_autoreply")]]
            )
            return
        
        if data == "go_premium":
            # Show plan selection menu for everyone
            plan_msg = (
                "**Choose Your Plan:**\n\n"
                "• Scout - Free starter plan\n"
                "• Grow - Scale your campaigns (₹69)\n"
                "• Prime - Advanced automation (₹199)\n"
                "• Dominion - Enterprise level (₹389)"
            )
            
            if PLAN_IMAGE_URL:
                try:
                    await event.delete()
                except:
                    pass
                await main_bot.send_file(uid, PLAN_IMAGE_URL, caption=plan_msg, buttons=plan_select_keyboard(uid))
            else:
                await event.edit(plan_msg, buttons=plan_select_keyboard(uid))
            return
        
        if data.startswith("buy_"):
            plan = data.replace("buy_", "")
            prices = {"1month": "$20", "3months": "$50", "6months": "$70"}
            price = prices.get(plan, "$20")
            
            owner_id = CONFIG['owner_id']
            try:
                await main_bot.send_message(owner_id, f"**Premium Purchase Request**\n\nUser ID: `{uid}`\nPlan: {plan}\nPrice: {price}")
            except:
                pass
            
            await event.edit(
                f"**Request Sent!**\n\nPlan: {plan}\nPrice: {price}\n\nAdmin has been notified.\nThey will contact you shortly.\n\nYour User ID: `{uid}`",
                buttons=[[Button.inline("Back", b"go_premium")]]
            )
            return
        
        if data == "account_limit_reached":
            await event.edit(
                "**Account Limit Reached**\n\nYou've reached the maximum accounts for your tier.\n\nUpgrade to Premium for more accounts!",
                buttons=[
                    [Button.inline("Buy Premium", b"go_premium")],
                    [Button.inline("Back", b"menu_account")]
                ]
            )
            return
        
        if data == "menu_logs":
            # Logs are now free for everyone
            logger_bot_username = CONFIG.get('logger_bot_username', 'logstesthubot')
            logger_link = f"https://t.me/{logger_bot_username}"
            
            await event.edit(
                "<b>📝 Logs Configuration</b>\n\n"
                "<blockquote>Logs are sent via Logger Bot with View Message buttons.\n\n"
                "To receive logs:\n"
                "1. Start the Logger Bot\n"
                "2. Click button below\n"
                "3. Enable logs for your accounts</blockquote>\n\n"
                "<i>Logs include forwarding activity with direct message links.</i>",
                parse_mode='html',
                buttons=[
                    [Button.url("Start Logger Bot", logger_link)],
                    [Button.inline("Configure Logs", b"logs_config")],
                    [Button.inline("Back", b"enter_dashboard")]
                ]
            )
            return
        
        # ===================== Smart Rotation (Premium) =====================
        if data == "menu_smart_rotation":
            if not is_premium(uid):
                await event.answer("⭐ Premium feature only!", alert=True)
                return
            
            # Check if user has any accounts
            user_accounts = list(accounts_col.find({"owner_id": uid}))
            if not user_accounts:
                await event.answer("❌ Please add an account first!", alert=True)
                return
            
            # Get user settings (stored separately with user_id)
            user_settings = users_col.find_one({"user_id": uid})
            if not user_settings:
                user_settings = {}
            current = user_settings.get('smart_rotation', False)
            
            await event.edit(
                "<b>🔄 Smart Rotation</b>\n\n"
                "<blockquote>When enabled, the bot will randomly shuffle the order of your target groups before each forwarding round.\n\n"
                "This makes your forwarding pattern unpredictable and more natural, helping avoid detection and rate limits.</blockquote>\n\n"
                f"<b>Status:</b> {'✅ Enabled' if current else '❌ Disabled'}",
                parse_mode='html',
                buttons=[
                    [Button.inline("✅ Enable" if not current else "❌ Disable", b"toggle_smart_rotation")],
                    [Button.inline("\u2190 Back", b"menu_settings")]
                ]
            )
            return
        
        if data == "toggle_smart_rotation":
            if not is_premium(uid):
                await event.answer("⭐ Premium feature only!", alert=True)
                return
            
            # Get current state from users collection
            user_settings = users_col.find_one({"user_id": uid})
            if not user_settings:
                user_settings = {}
            current = user_settings.get('smart_rotation', False)
            new_val = not current
            
            # Save to users collection
            users_col.update_one(
                {"user_id": uid},
                {"$set": {"smart_rotation": new_val}},
                upsert=True
            )
            
            await event.edit(
                "<b>🔄 Smart Rotation</b>\n\n"
                "<blockquote>When enabled, the bot will randomly shuffle the order of your target groups before each forwarding round.\n\n"
                "This makes your forwarding pattern unpredictable and more natural, helping avoid detection and rate limits.</blockquote>\n\n"
                f"<b>Status:</b> {'✅ Enabled' if new_val else '❌ Disabled'}",
                parse_mode='html',
                buttons=[
                    [Button.inline("✅ Enable" if not new_val else "❌ Disable", b"toggle_smart_rotation")],
                    [Button.inline("\u2190 Back", b"menu_settings")]
                ]
            )
            return
        
        # ===================== Auto Group Join (Premium) =====================
        if data == "menu_auto_group_join":
            if not is_premium(uid):
                await event.answer("⭐ Premium feature only!", alert=True)
                return
            
            # Check if user has any accounts
            user_accounts = list(accounts_col.find({"owner_id": uid}))
            if not user_accounts:
                await event.answer("❌ Please add an account first!", alert=True)
                return
            
            await event.edit(
                "<b>👥 Auto Group Join</b>\n\n"
                "<blockquote>Upload a .txt file with group links (one per line), and all your logged-in accounts will automatically join those groups.\n\n"
                "Supported formats:\n"
                "• https://t.me/groupname\n"
                "• t.me/groupname\n"
                "• @groupname</blockquote>\n\n"
                "Send the .txt file now, or tap Back to cancel.",
                parse_mode='html',
                buttons=[
                    [Button.inline("\u2190 Back", b"menu_settings")]
                ]
            )
            # Set user state to expect .txt file
            user_states[uid] = {'state': 'awaiting_group_join_file'}
            return
        
        
        if data == "logs_config":
            # Show old logs configuration for accounts
            
            accounts = get_user_accounts(uid)
            if not accounts:
                await event.answer("Add an account first!", alert=True)
                return
            
            if len(accounts) == 1:
                acc = accounts[0]
                account_id = str(acc['_id'])
                settings = get_account_settings(account_id)
                logs_chat = settings.get('logs_chat_id')

                if logs_chat:
                    text = (
                        "**Logs Configuration**\n\n"
                        f"Status: Enabled\nDM Target: `{logs_chat}`\n\n"
                        "Logs will be sent directly in your DM with View Message links."
                    )
                    buttons = [
                        [Button.inline("Disable DM Logs", f"clearlogs_{account_id}")],
                        [Button.inline("Back", b"enter_dashboard")]
                    ]
                else:
                    text = (
                        "**Logs Configuration**\n\n"
                        "Status: Disabled\n\n"
                        "Enable logs to receive them directly in DM."
                    )
                    buttons = [
                        [Button.inline("Enable DM Logs", f"enablelogs_{account_id}")],
                        [Button.inline("Back", b"enter_dashboard")]
                    ]

                await event.edit(text, parse_mode='html', buttons=buttons)
            else:
                text = "<b>Logs Configuration</b>\n\n<i>Select account to configure logs:</i>"
                buttons = []
                for acc in accounts:
                    phone = acc['phone'][-4:]
                    name = acc.get('name', 'Unknown')[:12]
                    settings = get_account_settings(str(acc['_id']))
                    status_icon = "Connected" if settings.get('logs_chat_id') else "Setup"
                    buttons.append([Button.inline(f"{phone} - {name} ({status_icon})", f"logs_acc_{acc['_id']}")])
                buttons.append([Button.inline("Back", b"enter_dashboard")])
                await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("logs_acc_"):
            account_id = data.replace("logs_acc_", "")

            settings = get_account_settings(account_id)
            logs_chat = settings.get('logs_chat_id')

            if logs_chat:
                status = f"Enabled (DM to you: `{logs_chat}`)"
                text = (
                    "**Logs Configuration**\n\n"
                    f"Status: {status}\n\n"
                    "Logs will be sent **directly in your DM** with View Message links."
                )
                buttons = [
                    [Button.inline("Disable DM Logs", f"clearlogs_{account_id}")],
                    [Button.inline("Back", b"menu_logs")]
                ]
            else:
                status = "Disabled"
                text = (
                    "**Logs Configuration**\n\n"
                    f"Status: {status}\n\n"
                    "Click below to enable logs in your DM."
                )
                buttons = [
                    [Button.inline("Enable DM Logs", f"enablelogs_{account_id}")],
                    [Button.inline("Back", b"menu_logs")]
                ]

            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("enablelogs_"):
            account_id = data.replace("enablelogs_", "")
            
            # Logs are now free for everyone - Send logs directly to this user's DM
            update_account_settings(account_id, {'logs_chat_id': int(uid)})
            await event.answer("DM logs enabled!", alert=True)
            await event.edit(
                "<b>✅ Logs Enabled</b>\n\n<i>You will now receive logs directly in DM.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back", f"acc_{account_id}")]]
            )
            return

        if data == "menu_fwd_mode":
            user = get_user(uid)
            current = user.get('forwarding_mode', 'topics')
            modes = {
                'topics': 'Forward to Topics Only',
                'auto': 'Forward to Auto Groups Only',
                'both': 'Forward to Both (Topics first, then Auto)'
            }
            
            text = (
                "<b>📤 Forwarding Mode</b>\n\n"
                "<blockquote>Select how ads should be forwarded.</blockquote>\n\n"
                f"<b>Current:</b> <code>{modes.get(current, 'Topics Only')}</code>"
            )
            
            buttons = []
            for mode, label in modes.items():
                mark = " (Current)" if mode == current else ""
                buttons.append([Button.inline(f"{label}{mark}", f"set_fwd_mode_{mode}")])
            buttons.append([Button.inline("← Back", b"enter_dashboard")])
            
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("set_fwd_mode_"):
            mode = data.replace("set_fwd_mode_", "")
            users_col.update_one({'user_id': uid}, {'$set': {'forwarding_mode': mode}})
            modes = {
                'topics': 'Forward to Topics Only',
                'auto': 'Forward to Auto Groups Only',
                'both': 'Forward to Both (Topics first, then Auto)'
            }
            await event.answer(f"Mode set: {modes.get(mode, mode)}", alert=True)
            
            text = (
                "<b>📤 Forwarding Mode</b>\n\n"
                "<blockquote>Select how ads should be forwarded.</blockquote>\n\n"
                f"<b>Current:</b> <code>{modes.get(mode, 'Topics Only')}</code>"
            )
            
            buttons = []
            for m, label in modes.items():
                mark = " (Current)" if m == mode else ""
                buttons.append([Button.inline(f"{label}{mark}", f"set_fwd_mode_{m}")])
            buttons.append([Button.inline("← Back", b"enter_dashboard")])
            
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data == "menu_refresh":
            accounts = get_user_accounts(uid)
            total_groups = 0
            for acc in accounts:
                try:
                    session = cipher_suite.decrypt(acc['session'].encode()).decode()
                    client = TelegramClient(StringSession(session), CONFIG['api_id'], CONFIG['api_hash'])
                    await client.connect()
                    count = await fetch_groups_for_account(client, acc['_id'])
                    total_groups += count
                    await client.disconnect()
                except:
                    pass
            await event.answer(f"Refreshed! Found {total_groups} groups.", alert=True)
            
            text = render_dashboard_text(uid)
            buttons = main_dashboard_keyboard(uid)
            # Admin button removed (already in main_dashboard_keyboard)
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data == "start_all_ads":
            # Update all added accounts profile (last name + bio) when starting ads
            try:
                await apply_account_profile_templates(uid)
            except Exception:
                pass

            accounts = get_user_accounts(uid)
            if not accounts:
                await event.answer("No accounts to start!", alert=True)
                return
            
            user = get_user(uid)
            fwd_mode = user.get('forwarding_mode', 'topics')
            
            started = 0
            for acc in accounts:
                acc_id = str(acc['_id'])
                is_fwd = acc.get('is_forwarding', False)
                
                print(f"[ADS DEBUG] Account {acc_id}: is_forwarding={is_fwd}, fwd_mode={fwd_mode}")
                
                if not is_fwd:
                    has_groups = False
                    if fwd_mode in ('topics', 'both'):
                        topic_count = account_topics_col.count_documents({'account_id': {'$in': _account_id_variants(acc['_id'])}})
                        print(f"[ADS DEBUG] Topics count: {topic_count}")
                        has_groups = topic_count > 0
                    if fwd_mode in ('auto', 'both') and not has_groups:
                        auto_count = account_auto_groups_col.count_documents({'account_id': {'$in': _account_id_variants(acc['_id'])}})
                        print(f"[ADS DEBUG] Auto groups count: {auto_count}")
                        has_groups = auto_count > 0
                    
                    print(f"[ADS DEBUG] has_groups={has_groups}")
                    
                    if has_groups:
                        accounts_col.update_one({'_id': acc['_id']}, {'$set': {'is_forwarding': True}})
                        
                        if acc['_id'] not in forwarding_tasks or forwarding_tasks[acc['_id']].done():
                            task = asyncio.create_task(run_forwarding_loop(uid, acc['_id']))
                            forwarding_tasks[acc['_id']] = task
                            print(f"[ADS] Started forwarding task for account {acc['_id']}")
                        
                        started += 1
                else:
                    print(f"[ADS DEBUG] Account {acc_id} already forwarding, skipped")
            
            print(f"[ADS] Started {started} accounts for user {uid}")
            await event.answer(f"Started {started} accounts!", alert=True)
            
            text = render_dashboard_text(uid)
            buttons = main_dashboard_keyboard(uid)
            # Admin button removed (already in main_dashboard_keyboard)
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data == "stop_all_ads":
            accounts = get_user_accounts(uid)
            stopped = 0
            for acc in accounts:
                if acc.get('is_forwarding'):
                    accounts_col.update_one({'_id': acc['_id']}, {'$set': {'is_forwarding': False}})
                    if acc['_id'] in forwarding_tasks:
                        forwarding_tasks[acc['_id']].cancel()
                        del forwarding_tasks[acc['_id']]
                    stopped += 1
            await event.answer(f"Stopped {stopped} accounts!", alert=True)
            
            text = render_dashboard_text(uid)
            buttons = main_dashboard_keyboard(uid)
            # Admin button removed (already in main_dashboard_keyboard)
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data == "tier_free":
            if not is_approved(uid):
                approve_user(uid)
            
            accounts = get_user_accounts(uid)
            max_acc = get_user_max_accounts(uid)
            tier_settings = get_user_tier_settings(uid)
            tier = "Premium" if is_premium(uid) else "Free"
            active = sum(1 for a in accounts if a.get('is_forwarding'))
            
            text = (
                f"<b>{tier} Dashboard</b>\n\n"
                f"<b>Accounts:</b> <code>{len(accounts)}/{max_acc}</code>\n"
                f"<b>Active:</b> <code>{active}</code> | <b>Inactive:</b> <code>{len(accounts) - active}</code>\n\n"
                f"<b>Delays:</b> <code>{tier_settings['msg_delay']}s/{tier_settings['group_delay']}s/{tier_settings['round_delay']}s</code>"
            )

            await event.edit(text, parse_mode='html', buttons=account_list_keyboard(uid))
            return
        
        if data == "tier_premium":
            if is_premium(uid):
                await event.edit(
                    "**Premium Active**\n\nYou already have premium access!",
                    buttons=[[Button.inline("Go to Dashboard", b"tier_free")], [Button.inline("Back", b"enter_dashboard")]]
                )
            else:
                await event.edit(
                    f"**Premium Access**\n\n{MESSAGES['premium_contact']}",
                    buttons=premium_contact_keyboard()
                )
            return
        
        if data == "admin_panel" or data == "back_admin":
            if not is_admin(uid):
                await event.answer("Admin only!", alert=True)
                return
            
            total_users = users_col.count_documents({})
            premium_users = users_col.count_documents({'tier': 'premium'})
            total_accounts = accounts_col.count_documents({})
            active = accounts_col.count_documents({'is_forwarding': True})
            total_admins = admins_col.count_documents({}) + 1
            
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            new_today = users_col.count_documents({'created_at': {'$gte': today_start}})
            
            text = (
                "<b>👑 Admin Panel</b>\n\n"
                f"<b>Total Users:</b> <code>{total_users}</code> <i>(+{new_today} today)</i>\n"
                f"<b>Premium Users:</b> <code>{premium_users}</code>\n"
                f"<b>Total Admins:</b> <code>{total_admins}</code>\n\n"
                f"<b>Total Accounts:</b> <code>{total_accounts}</code>\n"
                f"<b>Active Forwarding:</b> <code>{active}</code>\n\n"
                "<i>Use buttons below to manage bot.</i>"
            )
            
            await event.edit(text, parse_mode='html', buttons=admin_panel_keyboard())
            return
        
        if data == "admin_all_users":
            if not is_admin(uid):
                return

            page = 0
            per_page = 5
            users = list(users_col.find().sort('created_at', -1).skip(page*per_page).limit(per_page))
            total = users_col.count_documents({})
            total_pages = max(1, (total + per_page - 1) // per_page)

            text = f"<b>👥 All Users</b> <code>({total} total, page {page+1}/{total_pages})</code>\n\n"
            user_list = []
            buttons = []
            
            for u in users:
                user_id = u['user_id']
                username = u.get('username')
                
                # Try to fetch username from Telegram if not in database
                if not username:
                    username = await get_username_from_id(event.client, user_id)
                    if username:
                        # Update database with fetched username
                        users_col.update_one({'user_id': user_id}, {'$set': {'username': username}})
                
                # Add to display list
                if username:
                    user_list.append(f"@{username}")
                    label = f"View @{username}"
                else:
                    user_list.append(f"<code>{user_id}</code>")
                    label = f"View {user_id}"
                
                buttons.append([Button.inline(label, f"admin_user_detail_all_{user_id}")])
            
            text += "\n".join(user_list) if users else "<i>No users found.</i>"
            nav = []
            if page > 0:
                nav.append(Button.inline("<", f"admin_all_users_page_{page-1}"))
            if (page+1)*per_page < total:
                nav.append(Button.inline(">", f"admin_all_users_page_{page+1}"))
            if nav:
                buttons.append(nav)

            buttons.append([Button.inline("← Back", b"admin_panel")])
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("admin_all_users_page_"):
            if not is_admin(uid):
                return

            page = int(data.replace("admin_all_users_page_", ""))
            per_page = 5
            users = list(users_col.find().sort('created_at', -1).skip(page*per_page).limit(per_page))
            total = users_col.count_documents({})
            total_pages = max(1, (total + per_page - 1) // per_page)

            text = f"<b>👥 All Users</b> <code>({total} total, page {page+1}/{total_pages})</code>\n\n"
            user_list = []
            buttons = []
            
            for u in users:
                user_id = u['user_id']
                username = u.get('username')
                
                # Try to fetch username from Telegram if not in database
                if not username:
                    username = await get_username_from_id(event.client, user_id)
                    if username:
                        # Update database with fetched username
                        users_col.update_one({'user_id': user_id}, {'$set': {'username': username}})
                
                # Add to display list
                if username:
                    user_list.append(f"@{username}")
                    label = f"View @{username}"
                else:
                    user_list.append(f"<code>{user_id}</code>")
                    label = f"View {user_id}"
                
                buttons.append([Button.inline(label, f"admin_user_detail_all_{user_id}")])
            
            text += "\n".join(user_list) if users else "<i>No users found.</i>"
            nav = []
            if page > 0:
                nav.append(Button.inline("<", f"admin_all_users_page_{page-1}"))
            if (page+1)*per_page < total:
                nav.append(Button.inline(">", f"admin_all_users_page_{page+1}"))
            if nav:
                buttons.append(nav)

            buttons.append([Button.inline("← Back", b"admin_panel")])
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("admin_user_detail_all_"):
            if not is_admin(uid):
                return

            target_id = int(data.replace("admin_user_detail_all_", ""))
            user_detail_source = 'all'

        elif data.startswith("admin_user_detail_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_user_detail_", ""))
            user_detail_source = 'premium'
        
        # Common user detail display logic for both handlers
        if data.startswith("admin_user_detail_all_") or data.startswith("admin_user_detail_"):
            user = users_col.find_one({'user_id': target_id})
            
            if not user:
                await event.answer("User not found!", alert=True)
                return
            
            tier = user.get('tier', 'free')
            max_acc = user.get('max_accounts', 1)
            approved = user.get('approved', False)
            accounts = list(accounts_col.find({'owner_id': target_id}))
            active = sum(1 for a in accounts if a.get('is_forwarding'))
            
            created_at = user.get('created_at')
            created_str = created_at.strftime('%Y-%m-%d %H:%M') if hasattr(created_at, 'strftime') else str(created_at)
            
            # Show plan name and expiry instead of tier
            if is_admin(target_id):
                plan_display = "Admin"
                expiry_display = "999d"
            elif tier == 'premium':
                plan_name = user.get('plan_name', 'Premium')
                expires_at = user.get('premium_expires_at')
                if expires_at and isinstance(expires_at, datetime):
                    remaining = expires_at - datetime.now()
                    if remaining.total_seconds() > 0:
                        expiry_display = f"{remaining.days}d"
                    else:
                        expiry_display = "Expired"
                else:
                    expiry_display = "∞"
                plan_display = plan_name
            else:
                plan_display = "Scout: Free"
                expiry_display = "∞"
            
            text = (
                f"<b>👤 User Profile</b>\n\n"
                f"<b>ID:</b> <code>{target_id}</code>\n"
                f"<b>Plan:</b> <code>{plan_display}</code>\n"
                f"<b>Expiry:</b> <code>{expiry_display}</code>\n"
                f"<b>Approved:</b> {'✅' if approved else '❌'}\n"
                f"<b>Max Accounts:</b> <code>{max_acc}</code>\n"
                f"<b>Accounts:</b> <code>{len(accounts)}</code> <i>(active: {active})</i>\n"
                f"<b>Created:</b> <code>{created_str}</code>"
            )
            
            buttons = []
            if tier != 'premium':
                buttons.append([Button.inline("✅ Grant Premium", f"admin_grant_premium_{target_id}")])
            else:
                buttons.append([Button.inline("❌ Revoke Premium", f"admin_revoke_premium_{target_id}")])
            
            # Back button routing based on source list
            if user_detail_source == 'all':
                back_callback = b"admin_all_users"
            else:
                back_callback = b"admin_premium"
            buttons.append([Button.inline("← Back", back_callback)])
            
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("admin_grant_premium_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_grant_premium_", ""))
            
            # Show plan selection screen
            text = (
                f"<b>🎯 Select Plan for User {target_id}</b>\n\n"
                f"<i>Choose a plan to grant (30 days):</i>\n\n"
                f"<b>🔰 Scout:</b> Free Plan (1 account)\n"
                f"<b>📈 Grow:</b> 3 accounts, medium speed\n"
                f"<b>⭐ Prime:</b> 7 accounts, fast speed\n"
                f"<b>👑 Dominion:</b> 15 accounts, fastest speed"
            )
            
            buttons = [
                [Button.inline("🔰 Scout", f"admin_grant_scout_{target_id}")],
                [Button.inline("📈 Grow", f"admin_grant_grow_{target_id}")],
                [Button.inline("⭐ Prime", f"admin_grant_prime_{target_id}")],
                [Button.inline("👑 Dominion", f"admin_grant_dominion_{target_id}")],
                [Button.inline("← Back", f"admin_user_detail_{target_id}")]
            ]
            
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        # Handle individual plan grants
        if data.startswith("admin_grant_scout_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_grant_scout_", ""))
            plan = PLANS['scout']
            days = 30
            expires_at = datetime.now() + timedelta(days=days)
            
            users_col.update_one(
                {'user_id': target_id},
                {'$set': {
                    'tier': 'free',
                    'plan_name': plan['name'],
                    'max_accounts': plan['max_accounts'],
                    'approved': True
                }},
                upsert=True
            )
            
            # Send notification to user
            welcome_image = MESSAGES.get('welcome_image', '')
            notify_text = (
                "<b>🎉 Plan Activated!</b>\n\n"
                "<b>Plan:</b> Scout\n"
                "<b>Accounts:</b> 1\n"
                "<b>Validity:</b> 30 days\n\n"
                "<i>Your plan features are now active!</i>"
            )
            notify_buttons = [
                [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
            ]
            
            try:
                if welcome_image:
                    await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
                else:
                    await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
            except Exception:
                pass
            
            await event.answer("✅ Scout plan granted!", alert=True)
            await event.edit(
                f"<b>✅ Plan Granted</b>\n\n<i>User {target_id} now has Scout plan access.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back to Users", b"admin_all_users")]]
            )
            return
        
        if data.startswith("admin_grant_grow_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_grant_grow_", ""))
            plan = PLANS['grow']
            days = 30
            expires_at = datetime.now() + timedelta(days=days)
            
            users_col.update_one(
                {'user_id': target_id},
                {'$set': {
                    'tier': 'premium',
                    'plan_name': plan['name'],
                    'max_accounts': plan['max_accounts'],
                    'premium_expires_at': expires_at,
                    'approved': True
                }},
                upsert=True
            )
            
            # Send notification to user
            welcome_image = MESSAGES.get('welcome_image', '')
            notify_text = (
                "<b>🎉 Plan Activated!</b>\n\n"
                "<b>Plan:</b> Grow\n"
                "<b>Accounts:</b> 3\n"
                "<b>Validity:</b> 30 days\n\n"
                "<i>Your premium features are now active!</i>"
            )
            notify_buttons = [
                [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
            ]
            
            try:
                if welcome_image:
                    await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
                else:
                    await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
            except Exception:
                pass
            
            await event.answer("✅ Grow plan granted!", alert=True)
            await event.edit(
                f"<b>✅ Plan Granted</b>\n\n<i>User {target_id} now has Grow plan access.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back to Users", b"admin_all_users")]]
            )
            return
        
        if data.startswith("admin_grant_prime_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_grant_prime_", ""))
            plan = PLANS['prime']
            days = 30
            expires_at = datetime.now() + timedelta(days=days)
            
            users_col.update_one(
                {'user_id': target_id},
                {'$set': {
                    'tier': 'premium',
                    'plan_name': plan['name'],
                    'max_accounts': plan['max_accounts'],
                    'premium_expires_at': expires_at,
                    'approved': True
                }},
                upsert=True
            )
            
            # Send notification to user
            welcome_image = MESSAGES.get('welcome_image', '')
            notify_text = (
                "<b>🎉 Plan Activated!</b>\n\n"
                "<b>Plan:</b> Prime\n"
                "<b>Accounts:</b> 7\n"
                "<b>Validity:</b> 30 days\n\n"
                "<i>Your premium features are now active!</i>"
            )
            notify_buttons = [
                [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
            ]
            
            try:
                if welcome_image:
                    await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
                else:
                    await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
            except Exception:
                pass
            
            await event.answer("✅ Prime plan granted!", alert=True)
            await event.edit(
                f"<b>✅ Plan Granted</b>\n\n<i>User {target_id} now has Prime plan access.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back to Users", b"admin_all_users")]]
            )
            return
        
        if data.startswith("admin_grant_dominion_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_grant_dominion_", ""))
            plan = PLANS['dominion']
            days = 30
            expires_at = datetime.now() + timedelta(days=days)
            
            users_col.update_one(
                {'user_id': target_id},
                {'$set': {
                    'tier': 'premium',
                    'plan_name': plan['name'],
                    'max_accounts': plan['max_accounts'],
                    'premium_expires_at': expires_at,
                    'approved': True
                }},
                upsert=True
            )
            
            # Send notification to user
            welcome_image = MESSAGES.get('welcome_image', '')
            notify_text = (
                "<b>🎉 Plan Activated!</b>\n\n"
                "<b>Plan:</b> Dominion\n"
                "<b>Accounts:</b> 15\n"
                "<b>Validity:</b> 30 days\n\n"
                "<i>Your premium features are now active!</i>"
            )
            notify_buttons = [
                [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
            ]
            
            try:
                if welcome_image:
                    await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
                else:
                    await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
            except Exception:
                pass
            
            await event.answer("✅ Dominion plan granted!", alert=True)
            await event.edit(
                f"<b>✅ Plan Granted</b>\n\n<i>User {target_id} now has Dominion plan access.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back to Users", b"admin_all_users")]]
            )
            return
        
        if data.startswith("admin_revoke_premium_"):
            if not is_admin(uid):
                return
            
            target_id = int(data.replace("admin_revoke_premium_", ""))
            users_col.update_one(
                {'user_id': target_id},
                {'$set': {'tier': 'free', 'max_accounts': 1}}
            )
            await event.answer("❌ Premium revoked!", alert=True)
            
            await event.edit(
                f"<b>❌ Premium Revoked</b>\n\n<i>User {target_id} now has free tier.</i>",
                parse_mode='html',
                buttons=[[Button.inline("← Back to Premium Users", b"admin_premium")]]
            )
            return
        
        if data == "admin_premium":
            if not is_admin(uid):
                return
            
            users = get_premium_users()
            text = f"<b>\U0001F451 Premium Users</b> <code>({len(users) if users else 0} total)</code>\n\n"
            
            buttons = []
            if not users:
                text += "<i>No premium users yet.</i>"
            else:
                for u in users[:20]:
                    user_id = u.get('user_id')
                    max_acc = u.get('max_accounts', 5)
                    acc_count = accounts_col.count_documents({'owner_id': user_id})
                    username = u.get('username')
                    label_id = f"@{username}" if username else str(user_id)
                    label = f"\U0001F451 {label_id} ({acc_count}/{max_acc} acc)"
                    buttons.append([Button.inline(label, f"admin_user_detail_{user_id}")])
            
            buttons.append([Button.inline("← Back", b"admin_panel")])
            
            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data == "admin_stats":
            if not is_admin(uid):
                return
            
            total_sent = 0
            total_failed = 0
            total_auto_replies = 0
            for stat in account_stats_col.find({}):
                total_sent += stat.get('total_sent', 0)
                total_failed += stat.get('total_failed', 0)
                total_auto_replies += stat.get('auto_replies', 0)
            
            text = f"**Bot Statistics**\n\n"
            text += f"Total Messages Sent: {total_sent}\n"
            text += f"Total Failed: {total_failed}\n"
            text += f"Success Rate: {(total_sent / max(1, total_sent + total_failed) * 100):.1f}%\n"
            text += f"Total Auto Replies: {total_auto_replies}"
            
            await event.edit(text, buttons=[[Button.inline("Back", b"admin_panel")]])
            return
        
        if data == "admin_broadcast":
            if not is_admin(uid):
                return
            
            user_states[uid] = {'action': 'broadcast'}
            await event.respond("Send the message to broadcast to all users:")
            return
        
        if data.startswith("page_"):
            page = int(data.split("_")[1])
            accounts = get_user_accounts(uid)
            max_acc = get_user_max_accounts(uid)
            tier_settings = get_user_tier_settings(uid)
            tier = "Premium" if is_premium(uid) else "Free"
            
            text = f"**{tier} Dashboard** (Page {page+1})\n\nAccounts: {len(accounts)}/{max_acc}"
            await event.edit(text, buttons=account_list_keyboard(uid, page))
            return
        
        if data.startswith("acc_"):
            account_id = data.split("_")[1]
            acc = get_account_by_id(account_id)
            if not acc:
                await event.answer("Not found!", alert=True)
                return
            
            # Check if user has per-account config access (Prime/Dominion)
            if not has_per_account_config_access(uid):
                await event.answer("Per-account config is a Prime/Dominion feature!", alert=True)
                await event.edit(
                    "🔒 **Per-Account Configuration**\n\n"
                    "This feature allows you to customize settings for each account individually.\n\n"
                    "Available in:\n"
                    "• Prime Plan (₹199)\n"
                    "• Dominion Plan (₹389)\n\n"
                    "Use main dashboard settings to control all accounts together.",
                    buttons=[[Button.inline("⬆️ Upgrade Plan", b"go_premium")], [Button.inline("🏠 Dashboard", b"enter_dashboard")]]
                )
                return
            
            stats = get_account_stats(account_id)
            settings = get_account_settings(account_id)
            topics = account_topics_col.count_documents({'account_id': account_id})
            groups = account_auto_groups_col.count_documents({'account_id': account_id})
            
            status = "🟢 Running" if acc.get('is_forwarding') else "🔴 Stopped"
            
            text = (
                f"📱 **Account Details**\n\n"
                f"Phone: {acc['phone']}\n"
                f"Name: {acc.get('name', 'Unknown')}\n"
                f"Status: {status}\n\n"
                f"📊 **Statistics**\n"
                f"Topics: {topics}\n"
                f"Groups: {groups}\n"
                f"Messages Sent: {stats.get('total_sent', 0)}\n"
                f"Failed: {stats.get('total_failed', 0)}\n\n"
                f"⏱️ **Delays**\n"
                f"Message: {settings.get('msg_delay', 30)}s\n"
                f"Group: {settings.get('group_delay', 90)}s\n"
                f"Round: {settings.get('round_delay', 3600)}s"
            )
            
            await event.edit(text, buttons=account_menu_keyboard(account_id, acc, uid))
            return
        
        if data.startswith("topics_"):
            account_id = data.split("_")[1]
            acc = get_account_by_id(account_id)
            await event.edit(
                f"<b> Topics</b>\n<blockquote>Account: <code>{_h(acc['phone'])}</code></blockquote>",
                parse_mode='html',
                buttons=topics_menu_keyboard(account_id, uid)
            )
            return
        
        if data.startswith("topic_"):
            parts = data.split("_")
            account_id, topic = parts[1], parts[2]
            
            tier_settings = get_user_tier_settings(uid)
            max_groups = tier_settings.get('max_groups_per_topic', 10)
            
            links = list(account_topics_col.find({'account_id': account_id, 'topic': topic}))
            text = f"**{topic.capitalize()}** ({len(links)}/{max_groups} links)\n\n"
            
            for i, l in enumerate(links[:15], 1):
                text += f"{i}. {l['url']}\n"
            if len(links) > 15:
                text += f"...+{len(links)-15} more"
            
            if not links:
                text += "No links yet."
            
            await event.edit(text, buttons=[
                [Button.inline("Add", f"add_{account_id}_{topic}"), Button.inline("Clear", f"clear_{account_id}_{topic}")],
                [Button.inline("Back", f"topics_{account_id}")]
            ])
            return
        
        if data.startswith("auto_"):
            account_id = data.split("_")[1]
            groups = list(account_auto_groups_col.find({'account_id': account_id}))
            
            text = f"**Auto Groups** ({len(groups)})\n\n"
            for i, g in enumerate(groups[:15], 1):
                u = f"@{g['username']}" if g.get('username') else "Private"
                text += f"{i}. {g['title'][:20]} ({u})\n"
            if len(groups) > 15:
                text += f"...+{len(groups)-15} more"
            
            await event.edit(text, buttons=[[Button.inline("Back", f"topics_{account_id}")]])
            return
        
        if data.startswith("add_"):
            parts = data.split("_")
            account_id, topic = parts[1], parts[2]
            user_states[uid] = {'action': 'add_links', 'account_id': account_id, 'topic': topic}
            await event.respond(f"Send links for **{topic}** (one per line):")
            return
        
        if data.startswith("clear_"):
            parts = data.split("_")
            account_id, topic = parts[1], parts[2]
            result = account_topics_col.delete_many({'account_id': account_id, 'topic': topic})
            await event.answer(f"Deleted {result.deleted_count} links!")
            return
        
        if data.startswith("settings_"):
            account_id = data.split("_")[1]
            settings = get_account_settings(account_id)
            
            text = "**Settings**\n\n"
            text += f"Message Delay: {settings.get('msg_delay', 30)}s\n"
            text += f"Group Delay: {settings.get('group_delay', 90)}s (every 10 msgs)\n"
            text += f"Round Delay: {settings.get('round_delay', 3600)}s\n"
            
            tier_settings = get_user_tier_settings(uid)
            if tier_settings.get('auto_reply_enabled'):
                text += f"Auto-Reply: {settings.get('auto_reply', 'Default')[:40]}..."
            
            failed = account_failed_groups_col.count_documents({'account_id': account_id})
            text += f"\nFailed Groups: {failed}"
            
            await event.edit(text, buttons=settings_keyboard(account_id, uid))
            return
        
        if data.startswith("setmsg_"):
            account_id = data.split("_")[1]
            user_states[uid] = {'action': 'set_msg_delay', 'account_id': account_id}
            await event.respond("Enter message delay (minimum 3 seconds, max 300):")
            return
        
        if data.startswith("setgrp_"):
            account_id = data.split("_")[1]
            user_states[uid] = {'action': 'set_grp_delay', 'account_id': account_id}
            await event.respond("Enter group delay (10-600 seconds):")
            return
        
        if data.startswith("setround_"):
            account_id = data.split("_")[1]
            user_states[uid] = {'action': 'set_round_delay', 'account_id': account_id}
            await event.respond("Enter round delay (minimum 3600 seconds / 1 hour):")
            return
        
        if data.startswith("setreply_"):
            tier_settings = get_user_tier_settings(uid)
            if not tier_settings.get('auto_reply_enabled'):
                await event.answer("Premium feature!", alert=True)
                return
            account_id = data.split("_")[1]
            user_states[uid] = {'action': 'set_reply', 'account_id': account_id}
            await event.respond("Send new auto-reply message:")
            return
        
        if data.startswith("clearfailed_"):
            account_id = data.split("_")[1]
            clear_failed_groups(account_id)
            await event.answer("Cleared failed groups!")
            return
        
        if data.startswith("stats_"):
            account_id = data.split("_")[1]
            acc = get_account_by_id(account_id)
            stats = get_account_stats(account_id)
            failed = account_failed_groups_col.count_documents({'account_id': account_id})
            
            text = f"**Stats** - {acc['phone']}\n\n"
            text += f"Sent: {stats.get('total_sent', 0)}\n"
            text += f"Failed: {stats.get('total_failed', 0)}\n"
            text += f"Skipped: {failed}\n"
            
            last = stats.get('last_forward')
            text += f"Last: {last.strftime('%Y-%m-%d %H:%M') if last else 'Never'}"
            
            await event.edit(text, buttons=[
                [Button.inline("Reset", f"reset_{account_id}")],
                [Button.inline("Back", f"acc_{account_id}")]
            ])
            return
        
        if data.startswith("reset_"):
            account_id = data.split("_")[1]
            account_stats_col.update_one(
                {'account_id': account_id},
                {'$set': {'total_sent': 0, 'total_failed': 0}},
                upsert=True
            )
            await event.answer("Stats reset!")
            return
        
        if data.startswith("refresh_"):
            account_id = data.split("_")[1]
            acc = get_account_by_id(account_id)
            
            await event.answer("Refreshing...", alert=False)
            
            try:
                session = cipher_suite.decrypt(acc['session'].encode()).decode()
                client = TelegramClient(StringSession(session), CONFIG['api_id'], CONFIG['api_hash'])
                await client.connect()
                
                if await client.is_user_authorized():
                    count = await fetch_groups(client, account_id, acc['phone'])
                    await client.disconnect()
                    await event.answer(f"Found {count} groups!", alert=True)
                else:
                    await event.answer("Session expired!", alert=True)
            except Exception as e:
                await event.answer("Error!", alert=True)
            return
        
        if data.startswith("fwd_select_"):
            account_id = data.split("_")[2]
            await event.edit("**Start Forwarding**\n\nSelect where to forward:", buttons=forwarding_select_keyboard(account_id, uid))
            return
        
        if data.startswith("startfwd_"):
            parts = data.split("_")
            account_id = parts[1]
            topic = parts[2] if len(parts) > 2 else "all"
            
            acc = get_account_by_id(account_id)
            accounts_col.update_one({'_id': acc['_id']}, {'$set': {'is_forwarding': True, 'fwd_topic': topic}})
            
            if account_id not in forwarding_tasks:
                forwarding_tasks[account_id] = asyncio.create_task(forwarder_loop(account_id, topic, uid))
            
            await event.answer("Started!")
            await event.edit(f"Forwarding started!\n\nTopic: {topic}", buttons=[[Button.inline("Back", f"acc_{account_id}")]])
            return
        
        if data.startswith("stop_"):
            account_id = data.split("_")[1]
            acc = get_account_by_id(account_id)
            
            accounts_col.update_one({'_id': acc['_id']}, {'$set': {'is_forwarding': False}})
            
            if account_id in forwarding_tasks:
                forwarding_tasks[account_id].cancel()
                del forwarding_tasks[account_id]
            
            if account_id in auto_reply_clients:
                try:
                    await auto_reply_clients[account_id].disconnect()
                except:
                    pass
                del auto_reply_clients[account_id]
            
            await event.answer("Stopped!")
            await send_log(account_id, "Forwarding stopped")
            await event.edit("Forwarding stopped!", buttons=[[Button.inline("Back", f"acc_{account_id}")]])
            return
        
        if data.startswith("clearlogs_"):
            account_id = data.replace("clearlogs_", "")
            update_account_settings(account_id, {'logs_chat_id': None})
            await event.answer("Logs disabled!", alert=True)
            await event.edit("**Logs Disabled**\n\nLogs will no longer be sent in DM.", buttons=[
                [Button.inline("Back", f"acc_{account_id}")]
            ])
            return
        
        if data.startswith("logs_"):
            account_id = data.replace("logs_", "")
            
            # Logs are now free for everyone

            settings = get_account_settings(account_id)
            logs_chat = settings.get('logs_chat_id')

            if logs_chat:
                text = (
                    "**Logs Configuration**\n\n"
                    f"Status: Enabled\nDM Target: `{logs_chat}`\n\n"
                    "Logs will be sent in your DM with View Message links."
                )
                buttons = [
                    [Button.inline("Disable DM Logs", f"clearlogs_{account_id}")],
                    [Button.inline("Back", f"acc_{account_id}")]
                ]
            else:
                text = (
                    "**Logs Configuration**\n\n"
                    "Status: Disabled\n\n"
                    "Enable logs to receive them directly in DM."
                )
                buttons = [
                    [Button.inline("Enable DM Logs", f"enablelogs_{account_id}")],
                    [Button.inline("Back", f"acc_{account_id}")]
                ]

            await event.edit(text, parse_mode='html', buttons=buttons)
            return
        
        if data.startswith("delete_"):
            account_id = data.split("_")[1]
            await event.edit(
                "**Delete this account?**\n\nAll data will be removed!",
                buttons=[
                    [Button.inline("Yes", f"confirm_{account_id}"), Button.inline("No", f"acc_{account_id}")]
                ]
            )
            return
        
        if data.startswith("confirm_"):
            account_id = data.split("_")[1]
            acc = get_account_by_id(account_id)
            
            if acc:
                from bson.objectid import ObjectId
                accounts_col.delete_one({'_id': ObjectId(account_id)})
                account_topics_col.delete_many({'account_id': account_id})
                account_settings_col.delete_many({'account_id': account_id})
                account_stats_col.delete_many({'account_id': account_id})
                account_auto_groups_col.delete_many({'account_id': account_id})
                account_failed_groups_col.delete_many({'account_id': account_id})
                logger_tokens_col.delete_many({'account_id': account_id})
                
                if account_id in forwarding_tasks:
                    forwarding_tasks[account_id].cancel()
                    del forwarding_tasks[account_id]
                
                if account_id in auto_reply_clients:
                    try:
                        await auto_reply_clients[account_id].disconnect()
                    except:
                        pass
                    del auto_reply_clients[account_id]
            
            await event.answer("Deleted!")
            await event.edit("**Dashboard**", buttons=account_list_keyboard(uid))
            return
        
        if data == "host":
            if not is_approved(uid):
                approve_user(uid)
            
            accounts = get_user_accounts(uid)
            max_accounts = get_user_max_accounts(uid)
            
            if len(accounts) >= max_accounts:
                if is_premium(uid):
                    await event.answer(f"Limit reached ({max_accounts})", alert=True)
                else:
                    await event.answer("Upgrade to Premium for more accounts!", alert=True)
                return
            
            user_states[uid] = {'action': 'phone'}
            await event.respond("Send phone with country code:\n\nExample: `+919876543210`")
            return
        
        if data.startswith("otp_"):
            if uid not in user_states or user_states[uid].get('action') != 'otp':
                return
            
            digit = data.split("_")[1]
            otp = user_states[uid].get('otp', '')
            
            if digit == "cancel":
                if 'client' in user_states[uid]:
                    await user_states[uid]['client'].disconnect()
                del user_states[uid]
                await event.answer("Cancelled!")
                await event.delete()
                return
            elif digit == "back":
                otp = otp[:-1]
            else:
                otp += digit
            
            user_states[uid]['otp'] = otp
            
            if len(otp) == 5:
                await event.edit(f"Code: `{otp}`\n\nVerifying...")
                
                try:
                    client = user_states[uid]['client']
                    await client.sign_in(user_states[uid]['phone'], otp, phone_code_hash=user_states[uid]['hash'])
                    
                    me = await client.get_me()
                    session = client.session.save()
                    encrypted = cipher_suite.encrypt(session.encode()).decode()
                    
                    result = accounts_col.insert_one({
                        'owner_id': uid,
                        'phone': user_states[uid]['phone'],
                        'name': me.first_name or 'Unknown',
                        'session': encrypted,
                        'is_forwarding': False,
                        'added_at': datetime.now()
                    })
                    
                    account_id = str(result.inserted_id)
                    count = await fetch_groups(client, account_id, user_states[uid]['phone'])
                    await client.disconnect()
                    
                    del user_states[uid]
                    
                    print(f"[ACCOUNT] Added account for user {uid}, fetched {count} groups")
                    await event.edit(
                        f"**Account Added!**\n\n{me.first_name}\nFound {count} groups",
                        buttons=account_list_keyboard(uid)
                    )
                    
                except SessionPasswordNeededError:
                    user_states[uid]['action'] = '2fa'
                    await event.edit("**2FA Required**\n\nSend your password:")
                except PhoneCodeInvalidError:
                    user_states[uid]['otp'] = ''
                    await event.edit("Wrong code! Try again:", buttons=otp_keyboard())
                except Exception as e:
                    await event.edit(f"Error: {str(e)[:100]}")
                    if 'client' in user_states[uid]:
                        await user_states[uid]['client'].disconnect()
                    del user_states[uid]
            else:
                await event.edit(f"Code: `{otp}{'_' * (5-len(otp))}`", buttons=otp_keyboard())
            return
    
    except MessageNotModifiedError:
        pass
    except Exception as e:
        print(f"Callback error: {e}")
        await event.answer("Error!", alert=True)

@main_bot.on(events.NewMessage)
async def text_handler(event):
    uid = event.sender_id
    text = event.text.strip()
    
    if text.startswith('/'):
        return
    
    if uid not in user_states:
        return
    
    state = user_states[uid]
    action = state.get('action') if isinstance(state, dict) else None
    state_type = state.get('state') if isinstance(state, dict) else None
    
    # ===================== Payment Screenshot Handler =====================
    if state_type == 'awaiting_payment_screenshot':
        # User should send a photo (payment screenshot)
        request_id = state.get('request_id')
        if not request_id or request_id not in pending_upi_payments:
            await event.respond("⚠️ Payment request expired. Please start again.")
            del user_states[uid]
            return
        
        # Check if message has photo
        if not event.message.photo:
            await event.respond("📸 Please send a <b>photo</b> of your payment screenshot.", parse_mode='html')
            return
        
        pay_req = pending_upi_payments[request_id]
        pay_req['status'] = 'submitted'
        
        # Get admin list: OWNER + DB admins
        admin_ids = [BOT_CONFIG['owner_id']]
        db_admins = list(admins_col.find({}))
        for adm in db_admins:
            admin_ids.append(adm['user_id'])
        
        admin_ids = list(set(admin_ids))  # deduplicate
        
        # Build admin notification
        sender = await event.get_sender()
        username_display = f"@{pay_req['username']}" if pay_req.get('username') else 'No username'
        
        admin_text = (
            f"<b>💰 New Payment Screenshot</b>\n\n"
            f"<b>User ID:</b> <code>{pay_req['user_id']}</code>\n"
            f"<b>Username:</b> {username_display}\n"
            f"<b>Plan:</b> {pay_req['plan_name']}\n"
            f"<b>Amount:</b> ₹{pay_req['price']}\n\n"
            f"<b>UPI ID:</b> <code>{UPI_PAYMENT.get('upi_id', '')}</code>\n\n"
            f"Review the screenshot and approve/reject:"
        )
        
        admin_buttons = [
            [
                Button.inline("✅ Approve", f"payapprove_{request_id}".encode()),
                Button.inline("❌ Reject", f"payreject_{request_id}".encode())
            ]
        ]
        
        # Forward screenshot to all admins
        for admin_id in admin_ids:
            try:
                msg = await main_bot.send_message(
                    admin_id,
                    admin_text,
                    parse_mode='html',
                    file=event.message.photo,
                    buttons=admin_buttons
                )
                admin_payment_message_map[msg.id] = request_id
            except Exception as e:
                print(f"[PAYMENT] Failed to notify admin {admin_id}: {e}")
        
        # Confirm to user
        await event.respond(
            "<b>✅ Screenshot Submitted</b>\n\n"
            "Your payment is under review. You'll be notified once it's verified.\n\n"
            "<i>This usually takes a few minutes.</i>",
            parse_mode='html'
        )
        
        # Clear user state
        del user_states[uid]
        return
    
    # ===================== Auto Group Join File Handler =====================
    if state_type == 'awaiting_group_join_file':
        # User should send a .txt file with group links
        if not event.message.document:
            await event.respond("📄 Please send a .txt file with group links (one per line).", parse_mode='html')
            return
        
        # Check if premium
        if not is_premium(uid):
            await event.respond("⭐ Premium feature only!")
            del user_states[uid]
            return
        
        # Download file
        try:
            file_path = await event.message.download_media()
            
            # Read group links
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_lines = f.read().splitlines()
            
            # Parse group links
            group_links = []
            for line in raw_lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Extract username from various formats
                if 'https://t.me/' in line:
                    username = line.split('https://t.me/')[-1].strip('/')
                elif 't.me/' in line:
                    username = line.split('t.me/')[-1].strip('/')
                elif line.startswith('@'):
                    username = line[1:]
                else:
                    username = line
                
                if username:
                    group_links.append(username)
            
            # Clean up downloaded file
            import os
            try:
                os.remove(file_path)
            except:
                pass
            
            if not group_links:
                await event.respond("❌ No valid group links found in the file.")
                del user_states[uid]
                return
            
            await event.respond(f"<b>🔄 Processing {len(group_links)} groups...</b>\n\nJoining with all your accounts...", parse_mode='html')
            
            # Get all user's logged-in accounts
            user_accounts = list(accounts_col.find({"owner_id": uid}))
            if not user_accounts:
                await event.respond("❌ You have no logged-in accounts.")
                del user_states[uid]
                return
            
            total_joined = 0
            total_failed = 0
            
            # Join groups with each account
            for acc in user_accounts:
                account_id = acc['account_id']
                client = user_clients.get(account_id)
                if not client:
                    continue
                
                for username in group_links:
                    try:
                        # Get entity and join
                        entity = await client.get_entity(username)
                        from telethon.tl.functions.channels import JoinChannelRequest
                        await client(JoinChannelRequest(entity))
                        total_joined += 1
                        print(f"[{account_id}] Joined: {username}")
                        await asyncio.sleep(2)  # Delay between joins
                    except Exception as e:
                        total_failed += 1
                        print(f"[{account_id}] Failed to join {username}: {e}")
            
            # Report results
            await event.respond(
                f"<b>✅ Auto Group Join Complete</b>\n\n"
                f"<b>Groups:</b> {len(group_links)}\n"
                f"<b>Accounts:</b> {len(user_accounts)}\n"
                f"<b>Joined:</b> {total_joined}\n"
                f"<b>Failed:</b> {total_failed}",
                parse_mode='html'
            )
            
        except Exception as e:
            await event.respond(f"❌ Error processing file: {e}")
            print(f"[AUTO_JOIN] Error: {e}")
        
        # Clear user state
        del user_states[uid]
        return
    
    if action == 'broadcast':
        if not is_admin(uid):
            del user_states[uid]
            return
        
        users = get_all_users()
        sent = 0
        failed = 0
        for u in users:
            try:
                await main_bot.send_message(u['user_id'], f"**Announcement**\n\n{text}")
                sent += 1
            except:
                failed += 1
        
        del user_states[uid]
        await event.respond(f"Broadcast complete!\nSent: {sent}\nFailed: {failed}")
        return
    
    if action == 'custom_autoreply':
        if not is_premium(uid):
            del user_states[uid]
            await event.respond("Premium only!")
            return
        
        # Save custom auto-reply to ALL user's accounts in account_settings_col
        accounts = get_user_accounts(uid)
        if accounts:
            for acc in accounts:
                update_account_settings(str(acc['_id']), {'auto_reply': text})
        
        del user_states[uid]
        await event.respond(
            f"✅ <b>Custom auto-reply saved!</b>\n\n<i>Applied to all {len(accounts)} account(s)</i>",
            parse_mode='html',
            buttons=[[Button.inline("← Back to Auto Reply", b"menu_autoreply")]]
        )
        return
    
    if action == 'add_topic_link':
        topic = state.get('topic')
        acc_id = state.get('account_id')
        last_msg_id = state.get('last_msg_id')
        
        raw_links = text.strip().replace(',', '\n').split('\n')
        links = []
        for raw in raw_links:
            link = raw.strip()
            if not link:
                continue
            if '?' in link:
                link = link.split('?')[0]
            if link.startswith('@'):
                link = f"https://t.me/{link[1:]}"
            elif link.startswith('t.me/'):
                link = f"https://{link}"
            elif not link.startswith('https://t.me/'):
                continue
            if 't.me/' in link:
                links.append(link)
        
        if not links:
            await event.respond("Invalid! Send links like:\n`https://t.me/groupname/5`\n\nYou can send multiple links, one per line.")
            return
        
        tier_settings = get_user_tier_settings(uid)
        max_groups = tier_settings.get('max_groups_per_topic', 10)
        current_count = account_topics_col.count_documents({'account_id': acc_id, 'topic': topic})
        
        added = 0
        skipped = 0
        
        for link in links:
            if current_count + added >= max_groups:
                break
            
            existing = account_topics_col.find_one({'account_id': acc_id, 'topic': topic, 'link': link})
            if existing:
                skipped += 1
                continue
            
            parts = link.replace('https://t.me/', '').split('/')
            group_username = parts[0]
            topic_msg_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            display_title = f"{group_username}/{topic_msg_id}" if topic_msg_id else group_username
            
            account_topics_col.insert_one({
                'account_id': acc_id,
                'topic': topic,
                'link': link,
                'title': display_title,
                'topic_msg_id': topic_msg_id,
                'added_at': datetime.now()
            })
            added += 1
        
        new_count = current_count + added
        
        update_text = f"**{topic.title()}**\n\nGroups: {new_count}/{max_groups}\n"
        if added > 0:
            update_text += f"Added: {added}"
        if skipped > 0:
            update_text += f" | Skipped: {skipped} (duplicates)"
        update_text += "\n\n"
        
        groups = list(account_topics_col.find({'account_id': acc_id, 'topic': topic}).sort('added_at', -1).limit(5))
        for i, g in enumerate(groups):
            update_text += f"{i+1}. {g.get('title', 'Unknown')}\n"
        
        total = account_topics_col.count_documents({'account_id': acc_id, 'topic': topic})
        if total > 5:
            update_text += f"\n...and {total - 5} more"
        
        update_text += "\n\nSend more links or go back."
        
        if last_msg_id:
            try:
                await main_bot.edit_message(event.chat_id, last_msg_id, update_text, 
                    buttons=[[Button.inline("View All", f"view_topic_groups_{topic}_{acc_id}")], [Button.inline("Back to Topics", b"menu_topics")]])
                await event.delete()
            except:
                msg = await event.respond(update_text,
                    buttons=[[Button.inline("View All", f"view_topic_groups_{topic}_{acc_id}")], [Button.inline("Back to Topics", b"menu_topics")]])
                user_states[uid]['last_msg_id'] = msg.id
        else:
            msg = await event.respond(update_text,
                buttons=[[Button.inline("View All", f"view_topic_groups_{topic}_{acc_id}")], [Button.inline("Back to Topics", b"menu_topics")]])
            user_states[uid]['last_msg_id'] = msg.id
        return
    
    if action == 'custom_interval':
        step = state.get('step')
        try:
            val = int(text)
        except:
            await event.respond("Please enter a valid number!")
            return
        
        if step == 'group_delay':
            if val < 30 or val > 300:
                await event.respond("Enter a value between 30-300:")
                return
            user_states[uid]['group_delay'] = val
            user_states[uid]['step'] = 'msg_delay'
            await event.respond("Enter message delay in seconds (10-120):")
            return
        
        if step == 'msg_delay':
            if val < 10 or val > 120:
                await event.respond("Enter a value between 10-120:")
                return
            user_states[uid]['msg_delay'] = val
            user_states[uid]['step'] = 'round_delay'
            await event.respond("Enter round delay in seconds (600-86400):")
            return
        
        if step == 'round_delay':
            if val < 600 or val > 86400:
                await event.respond("Enter a value between 600-86400:")
                return
            
            custom_interval = {
                'group_delay': user_states[uid]['group_delay'],
                'msg_delay': user_states[uid]['msg_delay'],
                'round_delay': val
            }
            users_col.update_one({'user_id': uid}, {'$set': {'custom_interval': custom_interval, 'interval_preset': 'custom'}})
            del user_states[uid]
            await event.respond(
                f"**Custom Interval Saved!**\n\nGroup Delay: {custom_interval['group_delay']}s\nMessage Delay: {custom_interval['msg_delay']}s\nRound Delay: {custom_interval['round_delay']}s",
                buttons=[[Button.inline("Back to Dashboard", b"enter_dashboard")]]
            )
            return
    
    if not is_approved(uid):
        approve_user(uid)
    
    if action == 'phone':
        if not re.match(r'^\+\d{10,15}$', text):
            await event.respond("Invalid format!\n\nUse: `+919876543210`")
            return
        
        accounts = get_user_accounts(uid)
        max_accounts = get_user_max_accounts(uid)
        
        if len(accounts) >= max_accounts:
            del user_states[uid]
            await event.respond(f"Account limit reached ({max_accounts})!")
            return
        
        # Typewriter effect: progressive updates
        status_msg = await event.respond("Connecting...")
        await asyncio.sleep(0.6)
        await status_msg.edit("Connecting to server...")
        await asyncio.sleep(0.7)
        await status_msg.edit("Sending OTP...")
        
        try:
            proxy = get_next_proxy()
            proxy_info = f" via proxy" if proxy else ""
            print(f"[OTP] Sending code to {text}{proxy_info}")
            
            client = TelegramClient(StringSession(), CONFIG['api_id'], CONFIG['api_hash'], proxy=proxy)
            await client.connect()
            
            sent = await client.send_code_request(text)
            
            await asyncio.sleep(0.5)
            await status_msg.edit("OTP Sent!")
            
            user_states[uid] = {
                'action': 'otp',
                'client': client,
                'phone': text,
                'hash': sent.phone_code_hash,
                'proxy': proxy
            }
            
            await asyncio.sleep(0.4)
            await event.respond(
                "**OTP Sent**\n\n"
                "Enter the code you received.\n\n"
                "Format: `code1234` (if code is 1234)\n\n"
                "Example: `code12345`"
            )
            
        except PhoneNumberInvalidError:
            await status_msg.edit("Invalid phone number!")
            del user_states[uid]
        except Exception as e:
            await status_msg.edit(f"Failed to send OTP: {str(e)[:100]}")
            del user_states[uid]
    
    elif action == 'otp':
        # Accept code in format: code1234 (remove "code" prefix)
        otp_code = text
        if text.lower().startswith('code'):
            otp_code = text[4:].strip()
        
        if not otp_code.isdigit() or len(otp_code) < 4:
            await event.respond("Invalid code format!\n\nUse: `code12345` (if OTP is 12345)")
            return
        
        try:
            client = state['client']
            await client.sign_in(state['phone'], otp_code, phone_code_hash=state['hash'])
            
            # Check if 2FA enabled
            me = await client.get_me()
            
            # Login successful - save account
            session = client.session.save()
            encrypted = cipher_suite.encrypt(session.encode()).decode()
            
            result = accounts_col.insert_one({
                'owner_id': uid,
                'phone': state['phone'],
                'name': me.first_name or 'Unknown',
                'session': encrypted,
                'is_forwarding': False,
                'added_at': datetime.now()
            })
            
            account_id = str(result.inserted_id)
            count = await fetch_groups(client, account_id, state['phone'])
            await client.disconnect()
            
            del user_states[uid]
            
            # NEW: Show professional plan selection after login (with image)
            plan_msg = (
                f"**Account Successfully Added**\n\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"**Name:** {me.first_name}\n"
                f"**Phone:** {state['phone']}\n"
                f"**Groups Found:** {count}\n"
                f"━━━━━━━━━━━━━━━━━━━━\n\n"
                f"**💎 Choose Your Plan to Continue:**\n\n"
                f"• Scout - Free starter plan\n"
                f"• Grow - Scale your campaigns (₹69)\n"
                f"• Prime - Advanced automation (₹199)\n"
                f"• Dominion - Enterprise level (₹389)"
            )
            
            if PLAN_IMAGE_URL:
                await event.respond(file=PLAN_IMAGE_URL, message=plan_msg, buttons=plan_select_keyboard(uid))
            else:
                await event.respond(plan_msg, buttons=plan_select_keyboard(uid))
            
        except SessionPasswordNeededError:
            # 2FA required
            user_states[uid]['action'] = '2fa'
            await event.respond(
                "**2FA Enabled**\n\n"
                "Enter your **Cloud Password**:"
            )
        except PhoneCodeInvalidError:
            await event.respond("Invalid code! Try again:")
        except PhoneCodeExpiredError:
            await event.respond("Code expired! Use /start to retry.")
            if 'client' in state:
                await state['client'].disconnect()
            del user_states[uid]
        except Exception as e:
            await event.respond(f"Error: {str(e)[:100]}")
            if 'client' in state:
                await state['client'].disconnect()
            del user_states[uid]
    
    elif action == '2fa':
        try:
            client = state['client']
            await client.sign_in(password=text)
            
            me = await client.get_me()
            session = client.session.save()
            encrypted = cipher_suite.encrypt(session.encode()).decode()
            
            result = accounts_col.insert_one({
                'owner_id': uid,
                'phone': state['phone'],
                'name': me.first_name or 'Unknown',
                'session': encrypted,
                'is_forwarding': False,
                'added_at': datetime.now()
            })
            
            account_id = str(result.inserted_id)
            count = await fetch_groups(client, account_id, state['phone'])
            await client.disconnect()
            
            del user_states[uid]
            
            print(f"[ACCOUNT] Added account for user {uid}, fetched {count} groups")
            
            # NEW: Show professional plan selection after 2FA login (with image)
            plan_msg = (
                f"**Account Successfully Added**\n\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"**Name:** {me.first_name}\n"
                f"**Phone:** {state['phone']}\n"
                f"**Groups Found:** {count}\n"
                f"━━━━━━━━━━━━━━━━━━━━\n\n"
                f"**💎 Choose Your Plan to Continue:**\n\n"
                f"• Scout - Free starter plan\n"
                f"• Grow - Scale your campaigns (₹69)\n"
                f"• Prime - Advanced automation (₹199)\n"
                f"• Dominion - Enterprise level (₹389)"
            )
            
            if PLAN_IMAGE_URL:
                await event.respond(file=PLAN_IMAGE_URL, message=plan_msg, buttons=plan_select_keyboard(uid))
            else:
                await event.respond(plan_msg, buttons=plan_select_keyboard(uid))
            
        except PasswordHashInvalidError:
            await event.respond("Wrong password! Try again:")
        except Exception as e:
            await event.respond(f"Error: {str(e)[:100]}")
            if 'client' in state:
                await state['client'].disconnect()
            del user_states[uid]
    
    elif action == 'add_links':
        account_id = state['account_id']
        topic = state['topic']
        
        tier_settings = get_user_tier_settings(uid)
        max_groups = tier_settings.get('max_groups_per_topic', 10)
        current = account_topics_col.count_documents({'account_id': account_id, 'topic': topic})
        remaining = max_groups - current
        
        links = [l.strip() for l in text.splitlines() if 't.me/' in l][:remaining]
        added = 0
        
        for link in links:
            try:
                peer, url, topic_id = parse_link(link)
                account_topics_col.insert_one({
                    'account_id': account_id,
                    'topic': topic,
                    'url': url,
                    'peer': peer,
                    'topic_id': topic_id
                })
                added += 1
            except:
                continue
        
        del user_states[uid]
        
        total = account_topics_col.count_documents({'account_id': account_id, 'topic': topic})
        await event.respond(f"Added {added} links!\nTotal: {total}/{max_groups}")
    
    elif action == 'set_msg_delay':
        try:
            v = int(text)
            
            # Global minimum: 3 seconds
            if v < 3:
                await event.respond("Minimum: 3s (global limit)!")
                return
            if v > 300:
                await event.respond("Maximum: 300s!")
                return
            
            update_account_settings(state['account_id'], {'msg_delay': v})
            del user_states[uid]
            await event.respond(f"Message delay: {v}s")
        except:
            await event.respond("Invalid number!")
    
    elif action == 'set_grp_delay':
        try:
            v = int(text)
            tier_settings = get_user_tier_settings(uid)
            min_delay = tier_settings['group_delay']
            
            if v < min_delay:
                await event.respond(f"Minimum: {min_delay}s for your tier!")
                return
            if v > 600:
                await event.respond("Maximum: 600s!")
                return
            
            update_account_settings(state['account_id'], {'group_delay': v})
            del user_states[uid]
            await event.respond(f"Group delay: {v}s")
        except:
            await event.respond("Invalid number!")
    
    elif action == 'set_round_delay':
        try:
            v = int(text)
            
            # Global minimum: 3600 seconds (1 hour)
            if v < 3600:
                await event.respond("Minimum: 3600s (1 hour - global limit)!")
                return
            if v > 86400:
                await event.respond("Maximum: 86400s!")
                return
            
            update_account_settings(state['account_id'], {'round_delay': v})
            del user_states[uid]
            await event.respond(f"Round delay: {v}s")
        except:
            await event.respond("Invalid number!")
    
    elif action == 'set_reply':
        tier_settings = get_user_tier_settings(uid)
        if not tier_settings.get('auto_reply_enabled'):
            del user_states[uid]
            await event.respond("Premium feature only!")
            return
        
        update_account_settings(state['account_id'], {'auto_reply': text})
        del user_states[uid]
        await event.respond("Auto-reply updated!")

@logger_bot.on(events.NewMessage(pattern=r'^/start(?:@[\w_]+)?\s*(.*)$'))
async def logger_start(event):
    uid = event.sender_id
    args = event.pattern_match.group(1)
    
    if args:
        token_doc = logger_tokens_col.find_one({'token': args})
        if token_doc:
            user_states[f"log_{uid}"] = {'account_id': token_doc['account_id']}
            await event.respond(
                "**Logger Setup**\n\n"
                "1. Add me to a channel/group as admin\n"
                "2. Forward any message from that chat here\n\n"
                "Or send the chat ID directly."
            )
            return
    
    await event.respond(
        "**Welcome to Kabru Ads Logger Bot**\n\n"
        "This panel handles all your broadcast activity logs in real-time.\n"
        "Keep this chat open to stay updated on every action.\n\n"
        "To begin sending ads, start the main bot: @KabruAdsBot",
        _no_style=True
    )

@logger_bot.on(events.NewMessage)
async def logger_handler(event):
    uid = event.sender_id
    key = f"log_{uid}"
    
    if key not in user_states:
        return
    
    state = user_states[key]
    
    if event.forward:
        chat_id = event.forward.chat_id
    else:
        try:
            chat_id = int(event.text.strip())
        except:
            await event.respond("Forward a message from target chat or send ID!")
            return
    
    try:
        await logger_bot.send_message(chat_id, "Logger connected! You'll receive forwarding logs here.")
        
        update_account_settings(state['account_id'], {'logs_chat_id': chat_id})
        
        del user_states[key]
        await event.respond("Logs configured!")
        
    except Exception as e:
        await event.respond(f"Cannot send to that chat!\nMake sure I'm admin.\n\nError: {str(e)[:50]}")

async def forwarder_loop(account_id, selected_topic, user_id):
    print(f"[{account_id}] Starting forwarder (topic: {selected_topic})")
    
    acc = get_account_by_id(account_id)
    if not acc:
        return
    
    tier_settings = get_user_tier_settings(user_id)
    
    await send_log(account_id, f"Forwarding started\nAccount: {acc['phone']}\nTopic: {selected_topic}")
    
    while True:
        try:
            acc = get_account_by_id(account_id)
            if not acc or not acc.get('is_forwarding'):
                print(f"[{account_id}] Stopped")
                break
            
            settings = get_account_settings(account_id)
            msg_delay = max(settings.get('msg_delay', 30), tier_settings['msg_delay'])
            group_delay = max(settings.get('group_delay', 90), tier_settings['group_delay'])
            round_delay = max(settings.get('round_delay', 3600), tier_settings['round_delay'])
            auto_reply_msg = settings.get('auto_reply', MESSAGES['auto_reply'])
            reply_cooldown = settings.get('reply_cooldown', 300)
            
            try:
                session = cipher_suite.decrypt(acc['session'].encode()).decode()
                client = TelegramClient(StringSession(session), CONFIG['api_id'], CONFIG['api_hash'])
                await client.connect()
                
                if not await client.is_user_authorized():
                    print(f"[{account_id}] Session expired")
                    await send_log(account_id, "Session expired!")
                    await asyncio.sleep(60)
                    continue
                
                await client.start()
                
                ads = []
                async for msg in client.iter_messages('me', limit=10):
                    if msg.text or msg.media:
                        ads.append(msg)
                ads.reverse()
                
                if not ads:
                    print(f"[{account_id}] No ads in Saved Messages")
                    await send_log(account_id, "No ads found in Saved Messages!")
                    await client.disconnect()
                    await asyncio.sleep(60)
                    continue
                
                all_targets = []
                max_topics = tier_settings.get('max_topics', 3)
                
                if selected_topic != "all" and selected_topic in TOPICS[:max_topics]:
                    topic_links = list(account_topics_col.find({'account_id': account_id, 'topic': selected_topic}))
                    for t in topic_links:
                        group_key = t['url']
                        group_name = t.get('url', 'Unknown')
                        if not is_group_failed(account_id, group_key):
                            all_targets.append({'type': 'topic', 'data': t, 'key': group_key, 'name': group_name})
                
                auto_groups = list(account_auto_groups_col.find({'account_id': account_id}))
                topic_peers = set()
                
                if selected_topic != "all":
                    for t in all_targets:
                        if 'peer' in t['data']:
                            topic_peers.add(str(t['data']['peer']))
                
                for g in auto_groups:
                    group_key = str(g['group_id'])
                    group_name = g.get('title', 'Unknown')
                    if group_key not in topic_peers and not is_group_failed(account_id, group_key):
                        all_targets.append({'type': 'auto', 'data': g, 'key': group_key, 'name': group_name})
                
                active_waits = get_active_flood_waits(account_id)
                print(f"[{account_id}] Forwarding to {len(all_targets)} groups (flood waits: {active_waits})")
                await send_log(account_id, f"Starting round\nGroups: {len(all_targets)}\nFlood waits: {active_waits}")
                
                # ===================== Smart Rotation (Premium) =====================
                # Shuffle target order if enabled
                user_settings = users_col.find_one({"user_id": user_id})
                if user_settings and user_settings.get('smart_rotation', False):
                    import random
                    random.shuffle(all_targets)
                    print(f"[{account_id}] Smart rotation: targets shuffled")
                    await send_log(account_id, f"Smart rotation: {len(all_targets)} targets shuffled")
                
                sent = 0
                failed = 0
                skipped = 0
                
                for i, target in enumerate(all_targets):
                    try:
                        acc_check = get_account_by_id(account_id)
                        if not acc_check or not acc_check.get('is_forwarding'):
                            break
                        
                        group_name = target.get('name', 'Unknown')[:30]
                        group_key = target['key']
                        
                        wait_remaining = get_flood_wait(account_id, group_key)
                        if wait_remaining > 0:
                            skipped += 1
                            mins = wait_remaining // 60
                            print(f"[{account_id}] Skipped {group_name} (wait: {mins}m)")
                            continue
                        
                        msg = ads[i % len(ads)]
                        
                        sent_msg_id = None
                        current_topic_id = None
                        current_entity = None
                        
                        if target['type'] == 'topic':
                            data = target['data']
                            peer = data.get('peer')
                            current_topic_id = data.get('topic_id')
                            
                            if peer is None:
                                peer, _, current_topic_id = parse_link(data['url'])
                            
                            current_entity = await client.get_entity(peer)
                            group_name = getattr(current_entity, 'title', group_name)[:30]
                            
                            if current_topic_id:
                                sent_msg_id = await forward_message(client, current_entity, msg.id, msg.peer_id, current_topic_id)
                            else:
                                result = await client.forward_messages(current_entity, msg.id, 'me')
                                if result:
                                        if isinstance(result, list):
                                            sent_msg_id = result[0].id if len(result) > 0 else None

                                        else:


                                            sent_msg_id = result.id
                        else:
                            data = target['data']
                            group_id = data['group_id']
                            access_hash = data.get('access_hash')
                            is_channel = data.get('is_channel', True)
                            username = data.get('username')
                            
                            current_entity = None
                            if username:
                                try:
                                    current_entity = await client.get_entity(username)
                                except:
                                    pass
                            
                            if current_entity is None and access_hash:
                                try:
                                    if is_channel:
                                        current_entity = InputPeerChannel(channel_id=group_id, access_hash=access_hash)
                                    else:
                                        current_entity = InputPeerChat(chat_id=group_id)
                                except:
                                    pass
                            
                            if current_entity is None:
                                try:
                                    current_entity = await client.get_entity(group_id)
                                except:
                                    current_entity = await client.get_entity(int('-100' + str(group_id)))
                            
                            result = await client.forward_messages(current_entity, msg.id, 'me')
                            if result:
                                if result:
                                    if isinstance(result, list):
                                        sent_msg_id = result[0].id if len(result) > 0 else None
                                    else:
                                        sent_msg_id = result.id

                                    sent_msg_id = result.id
                        
                        sent += 1
                        print(f"[{account_id}] Sent to {group_name} ({i+1}/{len(all_targets)})")
                        
                        if sent_msg_id and current_entity:
                            view_link = build_message_link(current_entity, sent_msg_id, current_topic_id)
                            if view_link:
                                await send_log(account_id, None, view_link=view_link, group_name=group_name)
                        
                        await asyncio.sleep(msg_delay)
                        
                        if (i + 1) % 10 == 0:
                            print(f"[{account_id}] Group pause ({group_delay}s)")
                            await asyncio.sleep(group_delay)
                        
                    except FloodWaitError as e:
                        wait_secs = e.seconds
                        mins = wait_secs // 60
                        failed += 1
                        
                        set_flood_wait(account_id, group_key, group_name, wait_secs)
                        
                        print(f"[{account_id}] FloodWait {mins}m in {group_name}")
                        await asyncio.sleep(msg_delay)
                        
                    except (ChannelPrivateError, ChatWriteForbiddenError, UserBannedInChannelError) as e:
                        failed += 1
                        mark_group_failed(account_id, target['key'], str(e))
                        error_type = type(e).__name__
                        print(f"[{account_id}] Failed {group_name}: {error_type}")
                        await asyncio.sleep(msg_delay)
                        
                    except Exception as e:
                        error_str = str(e)
                        
                        wait_match = re.search(r'wait of (\d+) seconds', error_str, re.IGNORECASE)
                        if wait_match:
                            wait_secs = int(wait_match.group(1))
                            failed += 1
                            set_flood_wait(account_id, group_key, group_name, wait_secs)
                        elif 'Could not find' in error_str or 'entity' in error_str.lower():
                            failed += 1
                            mark_group_failed(account_id, target['key'], error_str[:100])
                        else:
                            failed += 1
                            print(f"[{account_id}] Error {group_name}: {error_str[:50]}")
                        
                        await asyncio.sleep(msg_delay)
                
                update_account_stats(account_id, sent=sent, failed=failed)
                
                log_msg = f"Round complete!\n\nSent: {sent}\nFailed: {failed}\nSkipped: {skipped}\nNext round: {round_delay}s"
                await send_log(account_id, log_msg)
                
                print(f"[{account_id}] Round done! Sent: {sent}, Failed: {failed}")
                print(f"[{account_id}] Waiting {round_delay}s...")
                
                await asyncio.sleep(round_delay)
                await client.disconnect()
                
            except Exception as e:
                print(f"[{account_id}] Loop error: {e}")
                await asyncio.sleep(60)
                
        except Exception as e:
            print(f"[{account_id}] Outer error: {e}")
            await asyncio.sleep(60)
    
    if account_id in forwarding_tasks:
        del forwarding_tasks[account_id]
    if account_id in auto_reply_clients:
        try:
            await auto_reply_clients[account_id].disconnect()
        except:
            pass
        del auto_reply_clients[account_id]
    
    await send_log(account_id, "Forwarding ended")
    print(f"[{account_id}] Forwarder ended")

async def main():
    print("\n" + "="*50)
    print("Starting Ads Bot...")
    print("="*50)
    
    try:
        await main_bot.start(bot_token=CONFIG['bot_token'])
        me = await main_bot.get_me()
        print(f"Main: @{me.username}")
    except Exception as e:
        print(f"Main bot failed: {e}")
        return
    
    try:
        if CONFIG['logger_bot_token']:
            await logger_bot.start(bot_token=CONFIG['logger_bot_token'])
            me = await logger_bot.get_me()
            print(f"Logger: @{me.username}")
    except Exception as e:
        print(f"Logger failed: {e}")
    
    print("="*50)
    print("Bot running!")
    print("="*50 + "\n")
    
    await asyncio.gather(
        main_bot.run_until_disconnected(),
        logger_bot.run_until_disconnected() if CONFIG['logger_bot_token'] else asyncio.sleep(0)
    )


# ===== ADMIN: Grant Premium Commands =====

@main_bot.on(events.CallbackQuery(pattern=b"^admin_grant_premium$"))
async def admin_grant_premium_menu(event):
    uid = event.sender_id
    if not is_admin(uid):
        await event.answer("Admin only", alert=True)
        return
    
    help_text = (
        "<b>💎 Grant Premium Commands</b>\n\n"
        "<b>Usage:</b>\n"
        "<code>/grow userid days</code> - Grant Grow plan (3 accounts)\n"
        "<code>/prime userid days</code> - Grant Prime plan (7 accounts)\n"
        "<code>/domi userid days</code> - Grant Dominion plan (15 accounts)\n\n"
        "<b>Examples:</b>\n"
        "<code>/grow 123456789 30</code>\n"
        "<code>/prime 987654321 60</code>\n"
        "<code>/domi 555444333 90</code>\n\n"
        "<i>User will receive instant notification with plan activation.</i>"
    )
    await event.edit(help_text, parse_mode='html', buttons=[[Button.inline("← Back", b"admin_panel")]])


@main_bot.on(events.NewMessage(pattern=r'^/grow (\d+) (\d+)'))
async def cmd_grow(event):
    if not is_admin(event.sender_id):
        return
    
    target_id = int(event.pattern_match.group(1))
    days = int(event.pattern_match.group(2))
    
    # Grant Grow plan (3 accounts)
    expires_at = datetime.now() + timedelta(days=days)
    users_col.update_one(
        {'user_id': target_id},
        {'$set': {
            'tier': 'premium',
            'max_accounts': 3,
            'plan_name': 'Grow',
            'premium_granted_at': datetime.now(),
            'premium_expires_at': expires_at,
            'approved': True
        }},
        upsert=True
    )
    
    # Send notification to user with image
    welcome_image = MESSAGES.get('welcome_image', '')
    notify_text = (
        "<b>🎉 Plan Activated!</b>\n\n"
        "<b>Plan:</b> Grow\n"
        "<b>Accounts:</b> 3\n"
        "<b>Validity:</b> " + str(days) + " days\n\n"
        "<i>Your premium features are now active!</i>"
    )
    notify_buttons = [
        [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
    ]
    
    try:
        if welcome_image:
            await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
        else:
            await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
        await event.respond(f"✅ Grow plan granted to {target_id} for {days} days")
    except Exception as e:
        await event.respond(f"✅ Granted but couldn't notify user: {e}")


@main_bot.on(events.NewMessage(pattern=r'^/prime (\d+) (\d+)'))
async def cmd_prime(event):
    if not is_admin(event.sender_id):
        return
    
    target_id = int(event.pattern_match.group(1))
    days = int(event.pattern_match.group(2))
    
    # Grant Prime plan (7 accounts)
    expires_at = datetime.now() + timedelta(days=days)
    users_col.update_one(
        {'user_id': target_id},
        {'$set': {
            'tier': 'premium',
            'max_accounts': 7,
            'plan_name': 'Prime',
            'premium_granted_at': datetime.now(),
            'premium_expires_at': expires_at,
            'approved': True
        }},
        upsert=True
    )
    
    # Send notification to user with image
    welcome_image = MESSAGES.get('welcome_image', '')
    notify_text = (
        "<b>🎉 Plan Activated!</b>\n\n"
        "<b>Plan:</b> Prime\n"
        "<b>Accounts:</b> 7\n"
        "<b>Validity:</b> " + str(days) + " days\n\n"
        "<i>Your premium features are now active!</i>"
    )
    notify_buttons = [
        [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
    ]
    
    try:
        if welcome_image:
            await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
        else:
            await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
        await event.respond(f"✅ Prime plan granted to {target_id} for {days} days")
    except Exception as e:
        await event.respond(f"✅ Granted but couldn't notify user: {e}")


@main_bot.on(events.NewMessage(pattern=r'^/domi (\d+) (\d+)'))
async def cmd_domi(event):
    if not is_admin(event.sender_id):
        return
    
    target_id = int(event.pattern_match.group(1))
    days = int(event.pattern_match.group(2))
    
    # Grant Dominion plan (15 accounts)
    expires_at = datetime.now() + timedelta(days=days)
    users_col.update_one(
        {'user_id': target_id},
        {'$set': {
            'tier': 'premium',
            'max_accounts': 15,
            'plan_name': 'Dominion',
            'premium_granted_at': datetime.now(),
            'premium_expires_at': expires_at,
            'approved': True
        }},
        upsert=True
    )
    
    # Send notification to user with image
    welcome_image = MESSAGES.get('welcome_image', '')
    notify_text = (
        "<b>🎉 Plan Activated!</b>\n\n"
        "<b>Plan:</b> Dominion\n"
        "<b>Accounts:</b> 15\n"
        "<b>Validity:</b> " + str(days) + " days\n\n"
        "<i>Your premium features are now active!</i>"
    )
    notify_buttons = [
        [Button.inline("Check Plans", b"back_plans"), Button.inline("Kabru Ads Now!", b"enter_dashboard")]
    ]
    
    try:
        if welcome_image:
            await main_bot.send_file(target_id, welcome_image, caption=notify_text, parse_mode='html', buttons=notify_buttons)
        else:
            await main_bot.send_message(target_id, notify_text, parse_mode='html', buttons=notify_buttons)
        await event.respond(f"✅ Dominion plan granted to {target_id} for {days} days")
    except Exception as e:
        await event.respond(f"✅ Granted but couldn't notify user: {e}")
if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        mongo_client.close()