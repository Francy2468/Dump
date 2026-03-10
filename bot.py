import discord
from discord.ext import commands
import requests
import os
import io
import urllib.parse
import subprocess
import uuid
import time
import re
import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Configuration — load sensitive values from environment variables so that
# credentials are never stored in source control.
# ---------------------------------------------------------------------------
TOKEN = os.environ.get("BOT_TOKEN", "")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
PREFIX = "."

# Path to the Lua dumper script (must live next to bot.py)
DUMPER_PATH = "envlogger.lua"

# Maximum input file size accepted by .l (5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# Wall-clock timeout (seconds) for a single dump run
DUMP_TIMEOUT = 60

# Minimum seconds a user must wait between .l invocations
COOLDOWN_SECONDS = 10

# Lua interpreters to try in order; first found one is used
LUA_INTERPRETERS = ["lua5.1", "lua5.4", "luajit", "lua"]

# ---------------------------------------------------------------------------
# Discord bot setup
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)

# Thread pool for blocking subprocess calls — keeps the async event loop free
_executor = ThreadPoolExecutor(max_workers=4)

# Per-user cooldown tracking  {user_id: last_used_timestamp}
_user_cooldowns: dict[int, float] = {}


# ---------------------------------------------------------------------------
# Lua interpreter discovery
# ---------------------------------------------------------------------------
def _find_lua() -> str:
    """Return the first available Lua interpreter name."""
    for interp in LUA_INTERPRETERS:
        try:
            r = subprocess.run(
                [interp, "-v"], capture_output=True, timeout=3
            )
            if r.returncode == 0:
                return interp
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return LUA_INTERPRETERS[0]  # fallback — will produce a clear error later


_lua_interp = _find_lua()


# ---------------------------------------------------------------------------
# Webhook helper
# ---------------------------------------------------------------------------
def send_to_webhook(
    user_id: int,
    user_name: str,
    action: str,
    details: str,
    output_preview: str | None = None,
) -> None:
    if not WEBHOOK_URL:
        return
    embed: dict = {
        "title": "🚨 Security Alert: Path Discovery Attempt",
        "color": 0xFF0000,
        "fields": [
            {"name": "User", "value": f"{user_name} ({user_id})", "inline": True},
            {"name": "Action", "value": action, "inline": True},
            {"name": "Details", "value": details, "inline": False},
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if output_preview:
        embed["fields"].append(
            {
                "name": "Output Preview",
                "value": f"```lua\n{output_preview[:1000]}\n```",
                "inline": False,
            }
        )
    try:
        requests.post(WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
    except Exception as exc:
        print(f"Webhook error: {exc}")


# ---------------------------------------------------------------------------
# Threat detection — pre-compiled patterns for speed
# ---------------------------------------------------------------------------
_THREAT_PATTERNS = [
    re.compile(r"getenv\(['\"]HOME['\"]\)", re.IGNORECASE),
    re.compile(r"getenv\(['\"]USER['\"]\)", re.IGNORECASE),
    re.compile(r"getenv\(['\"]PATH['\"]\)", re.IGNORECASE),
    re.compile(r"popen\(['\"]id['\"]\)", re.IGNORECASE),
    re.compile(r"getfenv\(\d+\)", re.IGNORECASE),
    re.compile(r"require\(['\"]ffi['\"]\)", re.IGNORECASE),
    re.compile(r"require\(['\"]lfs['\"]\)", re.IGNORECASE),
    re.compile(r"require\(['\"]io['\"]\)", re.IGNORECASE),
    re.compile(r"require\(['\"]os['\"]\)", re.IGNORECASE),
    re.compile(r"Environment\s+Auditor", re.IGNORECASE),
    re.compile(r"EnvAudit", re.IGNORECASE),
    re.compile(r"HOOK_DETECTION", re.IGNORECASE),
    re.compile(r"debug\.getinfo", re.IGNORECASE),
]


def detect_threats(text: str) -> tuple[bool, str | None]:
    for pat in _THREAT_PATTERNS:
        if pat.search(text):
            return True, pat.pattern
    return False, None


# ---------------------------------------------------------------------------
# URL / filename helpers
# ---------------------------------------------------------------------------
def extract_links(text: str) -> list[str]:
    url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.\-]*"
    links = re.findall(url_pattern, text)
    seen: set[str] = set()
    unique: list[str] = []
    for x in links:
        if x not in seen:
            seen.add(x)
            unique.append(x)
    return unique


def extract_first_url(text: str) -> str | None:
    match = re.search(r"https?://[^\s\"')]+", text)
    return match.group(0) if match else None


def get_filename_from_url(url: str) -> str:
    filename = url.split("/")[-1].split("?")[0]
    filename = urllib.parse.unquote(filename)
    return filename if (filename and "." in filename) else "script.lua"


# ---------------------------------------------------------------------------
# Pastefy upload
# ---------------------------------------------------------------------------
def upload_to_pastefy(
    content: str, title: str = "Dumped Script"
) -> tuple[str | None, str | None]:
    try:
        resp = requests.post(
            "https://pastefy.app/api/v2/paste",
            json={"title": title, "content": content, "visibility": "PUBLIC"},
            timeout=10,
        )
        if resp.status_code == 200:
            paste_id = resp.json().get("paste", {}).get("id")
            if paste_id:
                return (
                    f"https://pastefy.app/{paste_id}",
                    f"https://pastefy.app/{paste_id}/raw",
                )
    except Exception:
        pass
    return None, None


# ---------------------------------------------------------------------------
# Dumper — blocking implementation (runs in thread pool)
# ---------------------------------------------------------------------------
def _run_dumper_blocking(
    lua_content: bytes,
) -> tuple[bytes | None, float, int, int, str | None]:
    """
    Execute envlogger.lua against *lua_content* and return
    (dumped_bytes, exec_ms, loops, lines, error_string|None).
    """
    unique_id = str(uuid.uuid4())
    input_file = f"input_{unique_id}.lua"
    output_file = f"output_{unique_id}.lua"

    try:
        with open(input_file, "wb") as fh:
            fh.write(lua_content)

        start = time.time()
        result = subprocess.run(
            [_lua_interp, DUMPER_PATH, input_file, output_file],
            capture_output=True,
            timeout=DUMP_TIMEOUT,
        )
        exec_ms = (time.time() - start) * 1000

        stdout = result.stdout.decode(errors="ignore")

        # Parse stats emitted by envlogger.lua:
        #   "Lines: N | Remotes: N | Strings: N | Loops: N"
        loops = 0
        m = re.search(r"Loops:\s*(\d+)", stdout)
        if m:
            loops = int(m.group(1))

        lines = 0
        m = re.search(r"Lines:\s*(\d+)", stdout)
        if m:
            lines = int(m.group(1))

        if os.path.exists(output_file):
            with open(output_file, "rb") as fh:
                dumped = fh.read()
            return dumped, exec_ms, loops, lines, None

        stderr = result.stderr.decode(errors="ignore").strip()
        return None, 0, 0, 0, stderr or "Output file was not generated."

    except subprocess.TimeoutExpired:
        return (
            None,
            0,
            0,
            0,
            f"Dump timed out after {DUMP_TIMEOUT}s — the script may be too complex.",
        )
    except Exception as exc:
        return None, 0, 0, 0, str(exc)
    finally:
        for path in (input_file, output_file):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass


async def run_dumper(
    lua_content: bytes,
) -> tuple[bytes | None, float, int, int, str | None]:
    """Async wrapper: offloads the blocking dumper to the thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _executor, functools.partial(_run_dumper_blocking, lua_content)
    )


# ---------------------------------------------------------------------------
# Cooldown helper
# ---------------------------------------------------------------------------
def _cooldown_remaining(user_id: int) -> float:
    elapsed = time.time() - _user_cooldowns.get(user_id, 0)
    remaining = COOLDOWN_SECONDS - elapsed
    return remaining if remaining > 0 else 0.0


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
@bot.event
async def on_ready() -> None:
    print(f"Logged in as {bot.user} | Lua: {_lua_interp} | Prefix: {PREFIX}")


# ---------------------------------------------------------------------------
# .l — dump / deobfuscate a Lua script
# ---------------------------------------------------------------------------
@bot.command(name="l")
async def process_link(ctx: commands.Context, link: str | None = None) -> None:
    # Cooldown gate
    remaining = _cooldown_remaining(ctx.author.id)
    if remaining > 0:
        await ctx.send(
            f"⏳ Please wait **{remaining:.1f}s** before using this command again."
        )
        return

    content: bytes | None = None
    original_filename = "file"

    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        original_filename = att.filename
        if att.size > MAX_FILE_SIZE:
            await ctx.send(
                f"❌ Attachment too large (max {MAX_FILE_SIZE // 1024 // 1024} MB)."
            )
            return
        try:
            resp = requests.get(att.url, timeout=15)
            if resp.status_code == 200:
                content = resp.content
        except Exception as exc:
            await ctx.send(f"❌ Failed to download attachment: {exc}")
            return

    elif link:
        original_filename = get_filename_from_url(link)
        try:
            resp = requests.get(link, timeout=15)
            if resp.status_code == 200:
                if len(resp.content) > MAX_FILE_SIZE:
                    await ctx.send(
                        f"❌ File too large (max {MAX_FILE_SIZE // 1024 // 1024} MB)."
                    )
                    return
                content = resp.content
            else:
                await ctx.send(f"❌ Download failed (HTTP {resp.status_code}).")
                return
        except Exception as exc:
            await ctx.send(f"❌ Failed to download link: {exc}")
            return

    else:
        await ctx.send("Provide a link or attach a Lua file.")
        return

    if not content:
        await ctx.send("❌ Could not retrieve file content.")
        return

    # Record cooldown start immediately
    _user_cooldowns[ctx.author.id] = time.time()

    status_msg = await ctx.send("🔍 Scanning input for threats...")
    input_text = content.decode("utf-8", errors="ignore")
    is_threat, pattern = detect_threats(input_text)

    if is_threat:
        send_to_webhook(
            ctx.author.id,
            str(ctx.author),
            "Path Discovery Attempt (Input)",
            f"Pattern detected: `{pattern}`",
            input_text,
        )
        await status_msg.edit(content="🚨 Security violation detected. Incident reported.")
        return

    await status_msg.edit(content=f"⚙️ Deobfuscating… (timeout: {DUMP_TIMEOUT}s)")
    dumped_content, exec_ms, loops, lines, error = await run_dumper(content)

    if error:
        await status_msg.edit(content=f"❌ {error}")
        return

    dumped_text = dumped_content.decode("utf-8", errors="ignore")  # type: ignore[union-attr]
    is_threat_out, pattern_out = detect_threats(dumped_text)

    if is_threat_out:
        send_to_webhook(
            ctx.author.id,
            str(ctx.author),
            "Path Discovery Attempt (Output)",
            f"Pattern detected: `{pattern_out}`",
            dumped_text,
        )
        await status_msg.edit(
            content="🚨 Security violation detected in output. Incident reported."
        )
        return

    paste_url, raw_url = upload_to_pastefy(dumped_text, title=original_filename)
    found_links = extract_links(dumped_text)
    links_str = "\n".join(found_links[:5]) if found_links else "No links found."

    base_name = os.path.splitext(original_filename)[0]
    new_filename = f"{base_name}.lua.txt"

    preview_lines = dumped_text.splitlines()[:10]
    preview = "\n".join(preview_lines)
    if len(preview) > 500:
        preview = preview[:500] + "…"

    embed = discord.Embed(
        title=f"✅ Finished in {exec_ms:.2f} ms",
        description=f"**Pastefy Link:** {raw_url or 'N/A'}",
        color=0x2B2D31,
    )
    embed.add_field(
        name="🔗 Extracted Links",
        value=f"```\n{links_str}\n```",
        inline=False,
    )
    embed.add_field(
        name="📤 Script Output Preview",
        value=f"```lua\n{preview}\n```",
        inline=False,
    )
    embed.set_footer(
        text=f"⏱️ {exec_ms:.2f} ms | Lines: {lines} | Loops: {loops} | Catmio"
    )

    await status_msg.delete()
    await ctx.send(
        embed=embed,
        file=discord.File(io.BytesIO(dumped_content), filename=new_filename),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# .get — download any URL and attach it as a .txt file
# ---------------------------------------------------------------------------
@bot.command(name="get")
async def get_link_content(ctx: commands.Context, *, link: str | None = None) -> None:
    if not link:
        await ctx.send("Usage: `.get <link>`")
        return

    extracted = extract_first_url(link)
    if extracted:
        link = extracted

    status_msg = await ctx.send("⬇️ Downloading…")
    try:
        resp = requests.get(link, timeout=15)
        if resp.status_code == 200:
            filename = get_filename_from_url(link)
            if not filename.endswith(".txt"):
                filename = os.path.splitext(filename)[0] + ".txt"
            await status_msg.delete()
            await ctx.send(
                content=f"✅ Download complete: <{link}>",
                file=discord.File(io.BytesIO(resp.content), filename=filename),
            )
        else:
            await status_msg.edit(
                content=f"❌ Download failed (HTTP {resp.status_code})."
            )
    except Exception as exc:
        await status_msg.edit(content=f"❌ Error: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not TOKEN:
        print(
            "ERROR: BOT_TOKEN environment variable is not set.\n"
            "       Copy .env.example to .env and fill in your token."
        )
        raise SystemExit(1)
    bot.run(TOKEN)
