#!/usr/bin/env python3
"""github_upload_check の学習ストア。

学習内容（平文の秘密値は保存しない）:
  fingerprints: 確定した秘密値の HMAC-SHA256 指紋 → 同じ値がどこに出ても FAIL
  shapes:       値から導いた形（接頭辞＋文字種＋長さ）の正規表現 → 同じ形の別の値は WARN（推定のため）
  words:        秘密を代入していた変数名（危険Word） → その変数への代入を WARN

保存（暗号化＋分散）:
  鍵      macOS Keychain（account=ghcheck, service=github_upload_check）。使えなければ $GHCHECK_STORE_DIR/key
  本体    openssl aes-256-cbc(pbkdf2) で暗号化 + HMAC タグ → 乱数パッドで XOR 分割して2断片に
  断片1   $GHCHECK_STORE_DIR/learned.shard1（既定 ~/.config/github_upload_check/）
  断片2   $GHCHECK_SHARD2_DIR/learned.shard2（既定 ~/Library/Application Support/github_upload_check/）
片方の断片だけでは乱数と区別できない。鍵＋両断片が揃って初めて復号できる。
スクリプト・リポジトリの中には置かない。
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import subprocess
from pathlib import Path

STORE_DIR = Path(os.environ.get("GHCHECK_STORE_DIR") or Path.home() / ".config" / "github_upload_check")
SHARD2_DIR = Path(os.environ.get("GHCHECK_SHARD2_DIR") or Path.home() / "Library" / "Application Support" / "github_upload_check")
KEY_FILE = STORE_DIR / "key"                 # キーチェーンが使えないときの退避先
SHARD1 = STORE_DIR / "learned.shard1"
SHARD2 = SHARD2_DIR / "learned.shard2"
DATA_FILE = SHARD1                           # 表示用
KEYCHAIN = ("ghcheck", "github_upload_check")  # (account, service)
USE_KEYCHAIN = os.environ.get("GHCHECK_NO_KEYCHAIN") != "1"
EMPTY = {"fingerprints": {}, "shapes": {}, "words": {}}

CANDIDATE_RE = re.compile(r"[A-Za-z0-9_\-+/=.]{12,}")
IDENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")
PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]{1,6}[-_])")
NAME_HINT = re.compile(r"(?i)(key|token|secret|pass|api|auth|cred)")


def shannon(tok: str) -> float:
    n = len(tok)
    return -sum(c / n * math.log2(c / n) for c in {ch: tok.count(ch) for ch in set(tok)}.values())


# ---------- 鍵と暗号 ----------
def _keychain_get() -> bytes | None:
    r = subprocess.run(["security", "find-generic-password", "-a", KEYCHAIN[0], "-s", KEYCHAIN[1], "-w"],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return bytes.fromhex(r.stdout.strip())
    return None


def _keychain_set(k: bytes) -> bool:
    r = subprocess.run(["security", "add-generic-password", "-a", KEYCHAIN[0], "-s", KEYCHAIN[1], "-w", k.hex(), "-U"],
                       capture_output=True, text=True)
    return r.returncode == 0


_KEY_CACHE: bytes | None = None


def _key() -> bytes:
    global _KEY_CACHE
    if _KEY_CACHE:
        return _KEY_CACHE
    k = _keychain_get() if USE_KEYCHAIN else None
    if k is None and KEY_FILE.is_file():
        k = KEY_FILE.read_bytes()
    if k is None:
        k = secrets.token_bytes(32)
        if not (USE_KEYCHAIN and _keychain_set(k)):
            STORE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            KEY_FILE.write_bytes(k)
            KEY_FILE.chmod(0o600)
    _KEY_CACHE = k
    return k


def key_location() -> str:
    if USE_KEYCHAIN and _keychain_get() is not None:
        return "macOS Keychain"
    return str(KEY_FILE)


def _enc_pass(k: bytes) -> str:
    return hashlib.sha256(b"enc|" + k).hexdigest()


def _fp_key(k: bytes) -> bytes:
    return hashlib.sha256(b"fp|" + k).digest()


def fingerprint(value: str) -> str:
    return hmac.new(_fp_key(_key()), value.encode(), hashlib.sha256).hexdigest()


def _openssl(args: list[str], data: bytes, k: bytes) -> bytes:
    r = subprocess.run(["openssl", "enc", *args, "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", "env:GHCHECK_PASS"],
                       input=data, capture_output=True, env={**os.environ, "GHCHECK_PASS": _enc_pass(k)})
    if r.returncode != 0:
        raise RuntimeError(f"openssl 失敗: {r.stderr.decode(errors='replace').strip()[:200]}")
    return r.stdout


def _read_blob() -> bytes | None:
    if not SHARD1.is_file() and not SHARD2.is_file():
        return None
    if not (SHARD1.is_file() and SHARD2.is_file()):
        raise RuntimeError(f"学習ストアの断片が片方しかない: {SHARD1} / {SHARD2}")
    a, b = SHARD1.read_bytes(), SHARD2.read_bytes()
    if len(a) != len(b):
        raise RuntimeError("学習ストアの断片の長さが不一致（片方が古い）")
    return bytes(x ^ y for x, y in zip(a, b))


def _write_blob(blob: bytes) -> None:
    pad = secrets.token_bytes(len(blob))
    other = bytes(x ^ y for x, y in zip(blob, pad))
    for path, part in ((SHARD1, pad), (SHARD2, other)):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(part)
        tmp.chmod(0o600)
        tmp.replace(path)


def load() -> dict:
    blob = _read_blob()
    if blob is None:
        return json.loads(json.dumps(EMPTY))
    k = _key()
    tag, ct = blob[:32], blob[32:]
    if not hmac.compare_digest(tag, hmac.new(k, ct, hashlib.sha256).digest()):
        raise RuntimeError("学習ストアの改ざんか鍵不一致")
    return json.loads(_openssl(["-d"], ct, k).decode())


def save(data: dict) -> None:
    k = _key()
    ct = _openssl(["-e"], json.dumps(data, ensure_ascii=False).encode(), k)
    _write_blob(hmac.new(k, ct, hashlib.sha256).digest() + ct)


# ---------- 学習 ----------
def shape_of(value: str) -> str | None:
    m = PREFIX_RE.match(value)
    if not m:
        return None
    rest = value[m.end():]
    if len(rest) < 12 or shannon(rest) < 3.5:
        return None
    charset = "[A-Za-z0-9_\\-]" if re.fullmatch(r"[A-Za-z0-9_\-]+", rest) else "[A-Za-z0-9_\\-+/=.]"
    return r"\b" + re.escape(m.group(1)) + charset + "{" + str(max(12, int(len(rest) * 0.7))) + ",}"


def learn_value(data: dict, value: str, source: str, name: str | None = None) -> list[str]:
    """値1件を学習。戻り値は何を学んだかの要約。"""
    today = dt.date.today().isoformat()
    got = []
    value = value.strip().strip("'\"")
    if len(value) < 12 or shannon(value) < 3.0:
        return got
    if value.startswith(("/", "~", "./")) or "://" in value and "@" not in value:
        return got  # パスや認証情報なしURLは秘密ではない
    fp = fingerprint(value)
    if fp not in data["fingerprints"]:
        data["fingerprints"][fp] = {"date": today, "source": source, "hint": value[:4] + "…" + str(len(value))}
        got.append(f"指紋 {value[:4]}…({len(value)}文字)")
    sh = shape_of(value)
    if sh:
        ent = data["shapes"].setdefault(sh, {"date": today, "count": 0, "example": value[:6] + "…"})
        ent["count"] += 1
        got.append(f"形 {sh[:40]}")
    if name and NAME_HINT.search(name) or (name and len(name) >= 6):
        ent = data["words"].setdefault(name, {"date": today, "count": 0})
        ent["count"] += 1
        got.append(f"Word {name}")
    return got


def learn_line(data: dict, line: str, source: str) -> list[str]:
    name = None
    m = IDENT_RE.search(line)
    if m:
        name = m.group(1)
    got = []
    for tok in CANDIDATE_RE.findall(line):
        if name and tok == name:
            continue
        got += learn_value(data, tok, source, name)
    return got


KV_RE = re.compile(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*['"]?([^'"\s#]+)['"]?""")
JSON_KV_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_.-]*)"\s*:\s*"([^"]{12,})"')


def learn_env(data: dict) -> list[str]:
    got = []
    for k, v in os.environ.items():
        if NAME_HINT.search(k) and len(v) >= 12:
            got += learn_value(data, v, "env", k)
    return got


def learn_file(data: dict, path: Path) -> list[str]:
    got = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        for rx in (KV_RE, JSON_KV_RE):
            m = rx.match(line) if rx is KV_RE else rx.search(line)
            if m and len(m.group(2)) >= 12:
                got += learn_value(data, m.group(2), f"file:{path.name}", m.group(1))
    return got


# ---------- 検出側で使う ----------
def compiled(data: dict) -> dict:
    shapes = []
    for rx in data["shapes"]:
        try:
            shapes.append(re.compile(rx))
        except re.error:
            continue
    words = None
    if data["words"]:
        alt = "|".join(re.escape(w) for w in sorted(data["words"], key=len, reverse=True))
        words = re.compile(r"\b(" + alt + r")\b\s*[:=]\s*['\"]?[^'\"\s]{8,}")
    return {"fps": set(data["fingerprints"]), "shapes": shapes, "words": words}


def scan(text: str, comp: dict) -> list[tuple[str, int, str]]:
    """(label, pos, severity, matched) のリスト。severity: FAIL/WARN"""
    out = []
    if comp["fps"]:
        seen = set()
        for m in CANDIDATE_RE.finditer(text):
            tok = m.group()
            if len(tok) < 12 or tok in seen:
                continue
            seen.add(tok)
            if fingerprint(tok) in comp["fps"]:
                out.append(("学習済みの秘密値", m.start(), "FAIL", tok))
    for rx in comp["shapes"]:
        m = rx.search(text)
        if m:
            out.append((f"学習した形 {rx.pattern[:30]}", m.start(), "WARN", m.group()))
    if comp["words"]:
        m = comp["words"].search(text)
        if m:
            out.append((f"学習した危険Word {m.group(1)}", m.start(), "WARN", m.group()))
    return out


def status(data: dict) -> str:
    return (f"学習ストア: 指紋{len(data['fingerprints'])} 形{len(data['shapes'])} Word{len(data['words'])} "
            f"[鍵={key_location()} / 断片1={SHARD1} / 断片2={SHARD2}]")
