import os

BOT_CONFIG = {
    'api_id': int(os.getenv('TELEGRAM_API_ID', '33388685')),
    'api_hash': os.getenv('TELEGRAM_API_HASH', '8a39446c6f69527dbfbb8e0e6c6a146f'),
    'bot_token': os.getenv('BOT_TOKEN', '8458516790:AAGVNZ3prRmEERf4iz8QM9ff__R3Fun33Po'),
    'owner_id': int(os.getenv('OWNER_ID', '6670166083')),
    'access_password': os.getenv('ACCESS_PASSWORD', 'ADSREACHOP'),
    'mongo_uri': os.getenv('MONGO_URI', 'mongodb+srv://aztech:ayazahmed1122@cluster0.mhuaw3q.mongodb.net/kabruads_db?retryWrites=true&w=majority'),
    'db_name': os.getenv('MONGO_DB_NAME', 'kabruads_db'),
    'logger_bot_token': os.getenv('LOGGER_BOT_TOKEN', '8392058083:AAFHXooljI8VhzsKctouHHFyHMmxYmPpCG8'),
    'logger_bot_username': os.getenv('LOGGER_BOT_USERNAME', 'aztechloggersbot'),
}

# ===================== PLAN TIERS =====================
# Scout (Free), Grow (₹69), Prime (₹199), Dominion (₹389)

PLAN_SCOUT = {
    'name': 'Scout',
    'price': 0,
    'price_display': 'Free',
    'tagline': 'Perfect for beginners exploring automation',
    'emoji': '🔰',
    'max_accounts': 1,
    'group_delay': 180,
    'msg_delay': 60,
    'round_delay': 10800,
    'auto_reply_enabled': False,
    'max_topics': 2,
    'max_groups_per_topic': 10,
    'logs_enabled': False,
    'description': '1 account, slow delays, basic features',
}

PLAN_GROW = {
    'name': 'Grow',
    'price': 69,
    'price_display': '₹69',
    'tagline': 'Scale your reach with multiple accounts',
    'emoji': '📈',
    'max_accounts': 3,
    'group_delay': 120,
    'msg_delay': 45,
    'round_delay': 7200,
    'auto_reply_enabled': True,
    'max_topics': 5,
    'max_groups_per_topic': 50,
    'logs_enabled': True,
    'description': '3 accounts, medium delays, auto-reply + logs + 🔄 Smart Rotation + 👥 Auto Group Join',
}

PLAN_PRIME = {
    'name': 'Prime',
    'price': 199,
    'price_display': '₹199',
    'tagline': 'Advanced automation for serious marketers',
    'emoji': '⭐',
    'max_accounts': 7,
    'group_delay': 80,
    'msg_delay': 30,
    'round_delay': 5400,
    'auto_reply_enabled': True,
    'max_topics': 9,
    'max_groups_per_topic': 100,
    'logs_enabled': True,
    'description': '7 accounts, faster delays, full features + 🔄 Smart Rotation + 👥 Auto Group Join',
}

PLAN_DOMINION = {
    'name': 'Dominion',
    'price': 389,
    'price_display': '₹389',
    'tagline': 'Ultimate power for advertising domination',
    'emoji': '👑',
    'max_accounts': 15,
    'group_delay': 60,
    'msg_delay': 20,
    'round_delay': 3600,
    'auto_reply_enabled': True,
    'max_topics': 15,
    'max_groups_per_topic': 200,
    'logs_enabled': True,
    'description': '15 accounts, fastest delays, priority support + 🔄 Smart Rotation + 👥 Auto Group Join',
}

PLANS = {
    'scout': PLAN_SCOUT,
    'grow': PLAN_GROW,
    'prime': PLAN_PRIME,
    'dominion': PLAN_DOMINION,
}

# Backwards compat (old code references FREE_TIER/PREMIUM_TIER)
FREE_TIER = PLAN_SCOUT.copy()
PREMIUM_TIER = PLAN_DOMINION.copy()
ADMIN_USERNAME = "axcne"

MESSAGES = {
    'welcome': "Welcome to Ads Bot!\n\nManage your Telegram advertising campaigns with ease.",
    'welcome_image': os.getenv('WELCOME_IMAGE', 'https://i.postimg.cc/5NQ0xZBw/photo-2026-01-11-03-10-28.jpg'),

    # ===================== Account Profile Templates =====================
    # Applied to ALL added accounts when user opens dashboard (/start).
    # First name is preserved as-is.
    # Last name is forced to this tag (removes any existing last name).
    'account_last_name_tag': '| @kabruadsbot',
    # Bio is forced to this text (removes any existing bio).
    'account_bio': 'Smart Ads Automation • @Kabru_adbot',
    'support_link': os.getenv('SUPPORT_LINK', 'https://t.me/kabruadsbot'),
    'updates_link': os.getenv('UPDATES_LINK', 'https://t.me/kabruadsbot'),
    'premium_contact': "Contact admin to purchase Premium access.\n\nPremium Benefits:\n- More accounts\n- Faster delays\n- Auto-reply feature\n- Detailed logs\n- Priority support",
    
    # Privacy Policy
    'privacy_short': (
        "<b>📜 Privacy Policy & Terms of Service</b>\n\n"
        "<blockquote>By using Kabru Ads Bot, you acknowledge and agree to:\n\n"
        "<b>✓ Service Usage:</b>\n"
        "• Automated broadcasting across Telegram groups\n"
        "• Responsible and ethical use of the platform\n"
        "• Compliance with Telegram's Terms of Service\n\n"
        "<b>✓ Data & Privacy:</b>\n"
        "• Session data stored securely (encrypted)\n"
        "• Account credentials never shared\n"
        "• Analytics for service improvement only\n"
        "• No data sold to third parties\n\n"
        "<b>✓ Your Responsibility:</b>\n"
        "• Avoid spam or abusive content\n"
        "• Respect group rules and user privacy\n"
        "• Use reasonable delays between messages</blockquote>\n\n"
        "<i>We prioritize your security and privacy.</i>"
    ),
    'privacy_full_link': os.getenv('PRIVACY_URL', 'https://jarvisads.site/privacy'),
}

# ===================== Force Join (Config-based) =====================
# If enabled, users must join BOTH a channel and a group before using the bot.
# Use usernames (without @) so buttons can point to public links.
FORCE_JOIN = {
    'enabled': os.getenv('FORCE_JOIN_ENABLED', 'true').lower() in ('1', 'true', 'yes', 'on'),

    # Public @usernames (without @). Example: 'AdsReachUpdates'
    'channel_username': os.getenv('FORCE_JOIN_CHANNEL', 'kabruadsbot'),
    # group_username removed (no forced group join)

    # Lock screen visuals
    'image_url': os.getenv('FORCE_JOIN_IMAGE', 'https://i.postimg.cc/5NQ0xZBw/photo-2026-01-11-03-10-28.jpg'),
    'message': os.getenv(
        'FORCE_JOIN_MESSAGE',
        "**Access Locked**\n\nPlease join our **Channel** and **Group** to use this bot.\n\nAfter joining, click **Verify**."
    ),
}

# Plan selection screen image
PLAN_IMAGE_URL = os.getenv('PLAN_IMAGE_URL', 'https://i.postimg.cc/5NQ0xZBw/photo-2026-01-11-03-10-28.jpg')

# ===================== Payment Config =====================
# Manual UPI payment (no crypto)
UPI_PAYMENT = {
    'qr_image_url': os.getenv('UPI_QR_IMAGE_URL', 'https://i.postimg.cc/qMpTFSm0/upi.jpg'),
    'upi_id': os.getenv('UPI_ID', 'shouryagupta0076@oksbi'),
    'payee_name': os.getenv('UPI_PAYEE_NAME', 'Shourya Gupta'),
}

ADMIN_SETTINGS = {
    'default_premium_accounts': 5,
    'default_premium_days': 30,
}

INTERVAL_PRESETS = {
    'slow': {'group_delay': 180, 'msg_delay': 60, 'round_delay': 10800, 'name': 'Slow (Safe)'},
    'medium': {'group_delay': 120, 'msg_delay': 45, 'round_delay': 7200, 'name': 'Medium (Balanced)'},
    'fast': {'group_delay': 60, 'msg_delay': 20, 'round_delay': 3600, 'name': 'Fast (Risky)'},
}

TOPICS = ['instagram', 'exchange', 'twitter', 'telegram', 'minecraft', 'tiktok', 'youtube', 'whatsapp', 'other']

# Proxy configuration for account logins
# Format: list of proxy dicts with type, host, port, username (optional), password (optional)
# Types: 'socks5', 'socks4', 'http'
# Example: {'type': 'socks5', 'host': '127.0.0.1', 'port': 1080, 'username': None, 'password': None}
PROXIES = []

# Add proxies from environment variable if set (comma-separated: type:host:port or type:host:port:user:pass)
proxy_env = os.getenv('PROXIES', '')
if proxy_env:
    for p in proxy_env.split(','):
        parts = p.strip().split(':')
        if len(parts) >= 3:
            proxy = {
                'type': parts[0],
                'host': parts[1],
                'port': int(parts[2]),
                'username': parts[3] if len(parts) > 3 else None,
                'password': parts[4] if len(parts) > 4 else None
            }
            PROXIES.append(proxy)
