#!/usr/bin/env python3
"""GitHubへアップロード（push）する前の安全チェック。

検査項目:
  1. リポジトリ可視性: origin（または --repo）が PRIVATE でなければ FAIL
  2. 大きいファイル: 追跡ファイルが 100MB超 → FAIL（GitHubが拒否）、50MB超 → WARN
     --history 指定時は全履歴の blob も走査する（.gitignore 済みでも履歴に残る）
  3. 危険なファイル名: .env / 秘密鍵 / auth.json / cookie / token など → FAIL
  4. 秘密パターン: APIキー・トークン・秘密鍵ブロック等の文字列 → FAIL
     学習ストア（--learn-*）の指紋・形は FAIL、危険Word は WARN。ストアは暗号化して ~/.config 側に置く
     類似パターン（32/40/64桁hex・base64風・高エントロピー・分割連結・URL埋め込み認証）→ WARN
  5. 禁止ディレクトリ: 個人メモ・実行時状態など上げないと決めた dir → FAIL（.ghcheck.json の forbid_dirs）

使い方:
  python3 github_upload_check.py                 # リモートに無い差分だけ検査（既定）
  python3 github_upload_check.py --all           # HEAD の追跡ファイル全件
  python3 github_upload_check.py --all --dir src  # 特定ディレクトリ内の全件
入口（ラッパー）:
  ghcheck-dir [dir ...]   # ディレクトリ内の全件を検査（無指定はリポジトリ全体）
  ghcheck-commit          # push予定の差分だけ検査（--staged で commit 前）
  python3 github_upload_check.py --install-hook  # git push 時に自動実行させる
  python3 github_upload_check.py --accept        # 今回の疑いを確認済みとして記録
  GITHUB_UPLOAD_OK=1 git push                    # 承認して push（承認内容は baseline に残る）
  python3 github_upload_check.py --learn-secret src/x.py:12  # 検出を本物と確定して学習
  python3 github_upload_check.py --learn-env --learn-file .env  # 使用中の鍵を学習（値は指紋のみ保存）
  python3 github_upload_check.py --path /repo    # 別リポジトリ
  python3 github_upload_check.py --staged        # ステージ済みだけ（pre-commit用）
  python3 github_upload_check.py --history       # 履歴の大blobも走査
  python3 github_upload_check.py --repo owner/name  # 可視性確認先を明示
  python3 github_upload_check.py --forbid notes --forbid runtime  # 禁止dir上書き
  python3 github_upload_check.py --no-forbid     # 禁止dir検査を無効化
  python3 github_upload_check.py --rules my.json # 案件固有の規則を追加合成
  python3 github_upload_check.py --warn-only     # 止めずに警告だけ出す
  python3 github_upload_check.py --confirm       # WARNがあれば人の確認を要求（push前の正規手順）

検査項目の追加: 同梱の github_upload_check.rules.json（共通既定）、リポジトリ直下の .ghcheck.json（そのリポジトリ固有・自動読込）、
--rules で指定した追加ファイルの順に合成する。リストは追記、entropy は上書き。

終了コード: 0=PASS, 1=FAIL あり, 2=検査自体が実行不能, 3=HOLD（--confirm でWARN未承認）
限界: パターン走査のみ。「PASS」は「機密なし」の証明ではない。
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

sys_path_dir = os.path.dirname(os.path.abspath(__file__))
if sys_path_dir not in sys.path:
    sys.path.insert(0, sys_path_dir)
import ghcheck_learn as learn  # noqa: E402

HARD_LIMIT = 100 * 1024 * 1024
WARN_LIMIT = 50 * 1024 * 1024
MAX_SCAN_BYTES = 5 * 1024 * 1024  # これより大きいファイルは秘密パターン走査を省略

RULES_FILE = Path(__file__).with_name("github_upload_check.rules.json")


REPO_RULES_NAME = ".ghcheck.json"


def load_rules(extra: list[str], repo: Path | None = None) -> dict:
    """規則をJSONから読む。既定ファイル + --rules で指定した追加ファイルを順に合成（リストは追記）。

    JSON構造:
      dangerous_names:  [glob, ...]           ファイル名一致 → FAIL
      dangerous_warn:   [glob, ...]           ファイル名一致 → WARN
      secret_patterns:  [{"label": str, "regex": str}, ...]  本文一致 → FAIL
      warn_patterns:    [{"label": str, "regex": str}, ...]  本文一致 → WARN（止めない）
      entropy:          {"min_len": 20, "threshold": 4.0, "charset": regex}  高エントロピー文字列 → WARN
      ignore_line_keywords: [str, ...]  行にこの語があれば疑い判定から除外（sha256, commit 等）
      downgrade_globs:  [glob, ...]     一致するpath（tests/ 等）では secret_patterns の FAIL を WARN に格下げ
      allow_public:     [owner/name]    公開を意図したリポジトリ。PUBLIC でも FAIL にしない（.ghcheck.json に書く）
      forbid_dirs:      [dir, ...]            追跡ファイルが含まれる → FAIL
      skip_suffixes:    [".png", ...]         本文走査を省略する拡張子
    """
    rules = {"dangerous_names": [], "dangerous_warn": [], "secret_patterns": [], "warn_patterns": [], "forbid_dirs": [], "skip_suffixes": [], "ignore_line_keywords": [], "downgrade_globs": [], "allow_public": []}
    entropy = {"min_len": 20, "threshold": 4.0, "charset": "[A-Za-z0-9_\\-+/=]"}
    repo_rules = repo / REPO_RULES_NAME if repo else None
    for path in [RULES_FILE, *([repo_rules] if repo_rules else []), *map(Path, extra)]:
        if not path.is_file():
            if path is not RULES_FILE and path is not repo_rules:
                raise RuntimeError(f"規則ファイルが無い: {path}")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"規則ファイルのJSONが不正 {path}: {e}")
        entropy.update(data.get("entropy", {}))
        for k in rules:
            v = data.get(k, [])
            if not isinstance(v, list):
                raise RuntimeError(f"{path}: {k} はリストで書く")
            rules[k].extend(v)
    for key in ("secret_patterns", "warn_patterns"):
        compiled = []
        for ent in rules[key]:
            try:
                compiled.append((ent["label"], re.compile(ent["regex"])))
            except (KeyError, re.error) as e:
                raise RuntimeError(f"{key} の不正な項目 {ent!r}: {e}")
        rules[key] = compiled
    try:
        entropy["token_re"] = re.compile(entropy["charset"] + "{" + str(int(entropy["min_len"])) + ",}")
    except re.error as e:
        raise RuntimeError(f"entropy.charset が不正: {e}")
    rules["entropy"] = entropy
    ign = rules.pop("ignore_line_keywords", [])
    rules["ignore_line_re"] = re.compile("(?i)(" + "|".join(map(re.escape, ign)) + ")") if ign else None
    rules["skip_suffixes"] = {x.lower() for x in rules["skip_suffixes"]}
    return rules




def git(repo: Path, *args: str, check: bool = True) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


class Report:
    def __init__(self) -> None:
        self.fails: list[str] = []
        self.warns: list[str] = []
        self.infos: list[str] = []

    def fail(self, m: str) -> None: self.fails.append(m)
    def warn(self, m: str) -> None: self.warns.append(m)
    def info(self, m: str) -> None: self.infos.append(m)


def check_visibility(repo: Path, repo_slug: str | None, rep: Report, allow_public: list[str] | None = None) -> None:
    target = repo_slug
    if not target:
        remote = git(repo, "remote", "get-url", "origin", check=False).strip()
        if not remote:
            rep.warn("origin リモート未設定。可視性は確認できない（作成時は --private を明示）")
            return
        m = re.search(r"github\.com[:/]([^/]+/[^/.]+)", remote)
        if not m:
            rep.warn(f"origin が GitHub ではない: {remote}")
            return
        target = m.group(1)
    r = subprocess.run(["gh", "repo", "view", target, "--json", "visibility", "-q", ".visibility"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        rep.warn(f"gh repo view {target} 失敗（未作成か未認証）: {r.stderr.strip()[:120]}")
        return
    vis = r.stdout.strip().upper()
    if vis == "PRIVATE":
        rep.info(f"可視性 {target}: PRIVATE")
    elif target in (allow_public or []):
        rep.info(f"可視性 {target}: {vis}（allow_public で許可済み。秘密・禁止dir の検査は通常どおり）")
    else:
        rep.fail(f"可視性 {target}: {vis}（Private以外へのpushは禁止。意図した公開なら .ghcheck.json の allow_public に追加）")


def default_base(repo: Path) -> str | None:
    """リモートに既にある範囲を除くための基準ref。upstream → origin/main|master → None(全件)。"""
    up = git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}", check=False).strip()
    if up:
        return up
    for cand in ("origin/main", "origin/master"):
        if git(repo, "rev-parse", "--verify", "-q", cand, check=False).strip():
            return cand
    return None


def list_files(repo: Path, staged: bool, base: str | None) -> tuple[list[str], str]:
    if staged:
        out = git(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
        return [l for l in out.splitlines() if l], "staged"
    if base:
        if not git(repo, "rev-parse", "--verify", "-q", base, check=False).strip():
            raise RuntimeError(f"基準ref が無い: {base}")
        out = git(repo, "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD")
        return [l for l in out.splitlines() if l], f"{base}..HEAD の差分"
    out = git(repo, "ls-files")
    return [l for l in out.splitlines() if l], "HEAD tracked 全件"


def blob_size(repo: Path, rel: str, staged: bool) -> int:
    ref = f":{rel}" if staged else f"HEAD:{rel}"
    out = git(repo, "cat-file", "-s", ref, check=False).strip()
    if out.isdigit():
        return int(out)
    p = repo / rel
    return p.stat().st_size if p.is_file() else 0


def check_sizes(repo: Path, files: list[str], staged: bool, rep: Report) -> None:
    for f in files:
        sz = blob_size(repo, f, staged)
        if sz > HARD_LIMIT:
            rep.fail(f"100MB超: {f} ({sz/1048576:.0f}MB) GitHubが拒否する")
        elif sz > WARN_LIMIT:
            rep.warn(f"50MB超: {f} ({sz/1048576:.0f}MB)")


def check_history(repo: Path, rep: Report) -> None:
    objs = git(repo, "rev-list", "--objects", "--all")
    r = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)"],
                       input=objs, capture_output=True, text=True)
    big: dict[str, int] = {}
    for line in r.stdout.splitlines():
        parts = line.split(" ", 3)
        if len(parts) < 3 or parts[1] != "blob":
            continue
        sz = int(parts[2])
        name = parts[3] if len(parts) > 3 else parts[0]
        if sz > HARD_LIMIT and sz > big.get(name, 0):
            big[name] = sz
    for name, sz in sorted(big.items(), key=lambda x: -x[1]):
        rep.fail(f"履歴に100MB超blob: {name} ({sz/1048576:.0f}MB) .gitignoreでは解決しない。git filter-repo が必要（別承認）")
    if not big:
        rep.info("履歴に100MB超blobなし")


def check_names(files: list[str], rules: dict, rep: Report) -> None:
    for f in files:
        base = Path(f).name
        for pat, sink in [(p, rep.fail) for p in rules["dangerous_names"]] + [(p, rep.warn) for p in rules["dangerous_warn"]]:
            if fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(base.lower(), pat):
                sink(f"危険なファイル名: {f} (pattern {pat})")
                break


def check_secrets(repo: Path, files: list[str], staged: bool, rules: dict, rep: Report,
                  baseline: set[str], new_keys: list, learned: dict | None) -> None:
    for f in files:
        if Path(f).suffix.lower() in rules["skip_suffixes"]:
            continue
        ref = f":{f}" if staged else f"HEAD:{f}"
        r = subprocess.run(["git", "-C", str(repo), "cat-file", "-p", ref], capture_output=True)
        data = r.stdout if r.returncode == 0 else (repo / f).read_bytes() if (repo / f).is_file() else b""
        if not data or len(data) > MAX_SCAN_BYTES or b"\x00" in data[:4096]:
            continue
        text = data.decode("utf-8", errors="replace")
        downgraded = any(fnmatch.fnmatch(f, g) or fnmatch.fnmatch("/" + f, g) for g in rules["downgrade_globs"])
        for label, pat in rules["secret_patterns"]:
            m = pat.search(text)
            if m:
                line_no = text.count("\n", 0, m.start()) + 1
                if downgraded:
                    rep.warn(f"秘密パターン(テストpathのため格下げ)[{label}]: {f}:{line_no}")
                else:
                    rep.fail(f"秘密パターン[{label}]: {f}:{line_no}")
        if learned:
            for label, pos, sev, matched in learn.scan(text, learned):
                line_no = text.count("\n", 0, pos) + 1
                if sev == "FAIL":
                    rep.fail(f"学習検出[{label}]: {f}:{line_no}")
                    continue
                key = hashlib.sha1(f"学習:{label}|{f}|{matched}".encode()).hexdigest()
                if key in baseline:
                    continue
                new_keys.append((f"学習:{label}", f, key, matched))
                rep.warn(f"疑い[学習:{label}]: {f}:{line_no}")
        lines = text.split("\n")
        starts = [0]
        for ln in lines[:-1]:
            starts.append(starts[-1] + len(ln) + 1)

        def line_of(pos: int) -> int:
            lo, hi = 0, len(starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if starts[mid] <= pos: lo = mid
                else: hi = mid - 1
            return lo

        def suspect(label: str, matches: list) -> None:
            kept = []
            for m in matches:
                li = line_of(m.start())
                if rules["ignore_line_re"] and rules["ignore_line_re"].search(lines[li]):
                    continue
                key = hashlib.sha1(f"{label}|{f}|{m.group()}".encode()).hexdigest()
                if key in baseline:
                    continue
                kept.append((li + 1, key, m.group()))
            if kept:
                new_keys.extend((label, f, k, v) for _, k, v in kept)
                rep.warn(f"疑い[{label}]: {f}:{kept[0][0]}" + (f" 他{len(kept)-1}件" if len(kept) > 1 else ""))

        for label, pat in rules["warn_patterns"]:
            suspect(label, list(pat.finditer(text)))
        ent = rules["entropy"]
        high = [m for m in ent["token_re"].finditer(text)
                if shannon(m.group()) >= ent["threshold"]
                and re.search(r"[=:]", lines[line_of(m.start())][:max(0, m.start() - starts[line_of(m.start())])])]
        suspect(f"高エントロピー文字列 H>={ent['threshold']}", high)


BASELINE_NAME = ".github_upload_check.baseline.json"


def load_baseline(repo: Path) -> tuple[set[str], dict]:
    p = repo / BASELINE_NAME
    if not p.is_file():
        return set(), {"accepted": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"baseline が不正 {p}: {e}")
    return set(data.get("accepted", {})), data


def save_baseline(repo: Path, data: dict, new_keys: list, note: str) -> int:
    today = dt.date.today().isoformat()
    acc = data.setdefault("accepted", {})
    for label, f, key, _ in new_keys:
        acc[key] = {"label": label, "file": f, "date": today, "by": note}
    (repo / BASELINE_NAME).write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return len(new_keys)


HOOK_MARK = "# github_upload_check pre-push hook"


def install_hook(repo: Path) -> str:
    hooks_dir = Path(git(repo, "rev-parse", "--git-path", "hooks").strip())
    if not hooks_dir.is_absolute():
        hooks_dir = repo / hooks_dir
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-push"
    if hook.exists() and HOOK_MARK not in hook.read_text(errors="replace"):
        raise RuntimeError(f"既存の pre-push がある（手で統合する）: {hook}")
    script = Path(__file__).resolve()
    hook.write_text(f"""#!/bin/sh
{HOOK_MARK}
# 承認済みで通すとき: GITHUB_UPLOAD_OK=1 git push
exec python3 "{script}" --path "$(git rev-parse --show-toplevel)" --confirm
""")
    hook.chmod(0o755)
    return str(hook)


def shannon(tok: str) -> float:
    n = len(tok)
    return -sum(c / n * math.log2(c / n) for c in {ch: tok.count(ch) for ch in set(tok)}.values())


def check_forbidden(files: list[str], forbid: list[str], rep: Report) -> None:
    hits: dict[str, int] = {}
    for f in files:
        top = f.split("/", 1)[0]
        for d in forbid:
            if top == d or f.startswith(d.rstrip("/") + "/"):
                hits[d] = hits.get(d, 0) + 1
    for d, n in hits.items():
        rep.fail(f"禁止ディレクトリ {d}/ の追跡ファイル {n}件（個人文脈・実行時状態はアップロード対象外）")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", default=".", help="リポジトリのパス")
    ap.add_argument("--repo", help="owner/name。省略時は origin から推定")
    ap.add_argument("--staged", action="store_true", help="ステージ済みファイルだけ検査")
    ap.add_argument("--history", action="store_true", help="全履歴の100MB超blobも走査")
    ap.add_argument("--forbid", action="append", help="禁止ディレクトリ（複数可・既定を置換）")
    ap.add_argument("--no-forbid", action="store_true", help="禁止ディレクトリ検査を無効化")
    ap.add_argument("--since", help="この ref 以降の差分だけ検査（既定: upstream か origin/main。無ければ全件）")
    ap.add_argument("--all", action="store_true", help="差分ではなく HEAD の追跡ファイル全件を検査")
    ap.add_argument("--dir", action="append", default=[], help="このディレクトリ配下だけに絞る（複数可・--all と併用で全件走査を範囲限定）")
    ap.add_argument("--accept", action="store_true", help="今回出た疑いWARNを確認済みとして baseline に記録（次回から出ない）")
    ap.add_argument("--install-hook", action="store_true", help="pre-push hook として組み込む（git push 時に自動実行）")
    ap.add_argument("--learn-secret", action="append", default=[], metavar="FILE:LINE",
                    help="その行の値を本物の秘密として学習（指紋・形・変数名）。平文は保存しない")
    ap.add_argument("--learn-env", action="store_true", help="現在の環境変数（KEY/TOKEN/SECRET等）から使用中の鍵を学習")
    ap.add_argument("--learn-file", action="append", default=[], help=".env や credentials JSON から使用中の鍵を学習（ファイル自体は上げない）")
    ap.add_argument("--learn-status", action="store_true", help="学習ストアの件数を表示")
    ap.add_argument("--forget-all", action="store_true", help="学習ストアを消去")
    ap.add_argument("--no-learned", action="store_true", help="学習ストアを検出に使わない")
    ap.add_argument("--rules", action="append", default=[], help="追加の規則JSON（複数可）。既定ファイルに追記合成")
    ap.add_argument("--confirm", action="store_true", help="WARNがあれば端末で確認を求め、承認なしなら exit 3（アップロード前ゲート）")
    ap.add_argument("--verbose", action="store_true", help="疑いWARNを集約せず全件表示")
    ap.add_argument("--warn-only", action="store_true", help="FAILもWARNに格下げして止めない（exit 0）")
    ap.add_argument("--skip-visibility", action="store_true", help="gh による可視性確認を省略")
    a = ap.parse_args()

    repo = Path(a.path).resolve()
    if git(repo, "rev-parse", "--is-inside-work-tree", check=False).strip() != "true":
        print(f"FAIL: {repo} は git リポジトリではない")
        return 2

    if a.install_hook:
        try:
            print(f"installed: {install_hook(repo)}")
            return 0
        except RuntimeError as e:
            print(f"FAIL: {e}")
            return 2

    if a.learn_secret or a.learn_env or a.learn_file or a.learn_status or a.forget_all:
        try:
            if a.forget_all:
                learn.save(json.loads(json.dumps(learn.EMPTY)))
                print("学習ストアを消去")
            data = learn.load()
            got = []
            for spec in a.learn_secret:
                f, _, ln = spec.rpartition(":")
                lines = (repo / f).read_text(encoding="utf-8", errors="replace").split("\n")
                got += learn.learn_line(data, lines[int(ln) - 1], f"{f}:{ln}")
            if a.learn_env:
                got += learn.learn_env(data)
            for lf in a.learn_file:
                got += learn.learn_file(data, Path(lf))
            if got:
                learn.save(data)
                print("学習: " + " / ".join(got))
            print(learn.status(data))
        except (RuntimeError, OSError, ValueError, IndexError) as e:
            print(f"FAIL: 学習失敗: {e}")
            return 2
        return 0

    rep = Report()
    new_keys: list = []
    try:
        rules = load_rules(a.rules, repo)
        learned = None
        if not a.no_learned:
            ldata = learn.load()
            learned = learn.compiled(ldata)
            if any(ldata.values()):
                rep.info(learn.status(ldata))
        baseline, baseline_data = load_baseline(repo)
        if baseline:
            rep.info(f"baseline: 確認済み {len(baseline)}件を除外 ({BASELINE_NAME})")
        srcs = RULES_FILE.name + (f"+{REPO_RULES_NAME}" if (repo / REPO_RULES_NAME).is_file() else "") + ("+" + ",".join(a.rules) if a.rules else "")
        rep.info(f"規則: 危険名{len(rules['dangerous_names'])+len(rules['dangerous_warn'])} 秘密パターン{len(rules['secret_patterns'])} 禁止dir{len(rules['forbid_dirs'])} ({srcs})")
        if not a.skip_visibility:
            check_visibility(repo, a.repo, rep, rules["allow_public"])
        base = None if (a.all or a.staged) else (a.since or default_base(repo))
        files, scope = list_files(repo, a.staged, base)
        if a.dir:
            dirs = []
            for d in a.dir:
                rel = os.path.relpath(Path(d).resolve(), repo) if os.path.isabs(d) or Path(d).exists() else d
                dirs.append(rel.strip("/").rstrip("/"))
            files = [f for f in files if any(f == d or f.startswith(d + "/") for d in dirs)]
            scope += " / dir=" + ",".join(dirs)
        rep.info(f"検査対象: {len(files)}ファイル ({scope})")
        check_sizes(repo, files, a.staged, rep)
        if a.history:
            check_history(repo, rep)
        check_names(files, rules, rep)
        check_secrets(repo, files, a.staged, rules, rep, baseline, new_keys, learned)
        if not a.no_forbid:
            check_forbidden(files, a.forbid or rules["forbid_dirs"], rep)
    except RuntimeError as e:
        print(f"FAIL: {e}")
        return 2

    if a.warn_only and rep.fails:
        rep.warns += [f"(warn-only) {m}" for m in rep.fails]
        rep.fails = []
    for m in rep.infos: print(f"INFO  {m}")
    suspects = [m for m in rep.warns if m.startswith("疑い[")]
    for m in rep.warns:
        if a.verbose or m not in suspects:
            print(f"WARN  {m}")
    if suspects and not a.verbose:
        groups: dict[str, list[str]] = {}
        for m in suspects:
            label, _, loc = m.partition("]: ")
            groups.setdefault(label + "]", []).append(loc.split(" 他")[0])
        print(f"WARN  疑い {len(suspects)}件（ファイル単位・--verbose で全件）")
        for label, locs in sorted(groups.items(), key=lambda x: -len(x[1])):
            more = f" …他{len(locs)-5}" if len(locs) > 5 else ""
            print(f"      {label} {len(locs)}件: " + ", ".join(locs[:5]) + more)
    for m in rep.fails: print(f"FAIL  {m}")
    print()
    print("限界: パターン走査のみ。履歴中の秘密（--history無しの大blob含む）やパターン外の秘密は検出しない。")
    approved_env = os.environ.get("GITHUB_UPLOAD_OK") == "1"
    if new_keys and (a.accept or approved_env):
        n = save_baseline(repo, baseline_data, new_keys, "GITHUB_UPLOAD_OK" if approved_env else "--accept")
        print(f"INFO  baseline に {n}件を確認済みとして記録")
    if rep.fails:
        print(f"結果: FAIL ({len(rep.fails)}件) push停止")
        return 1
    if rep.warns and a.confirm and approved_env:
        print(f"結果: PASS（WARN {len(rep.warns)}件、GITHUB_UPLOAD_OK=1 で承認済み）")
        return 0
    if rep.warns and a.confirm:
        if not sys.stdin.isatty():
            print(f"結果: HOLD (WARN {len(rep.warns)}件) 非対話環境のため確認不能。承認者の確認後に GITHUB_UPLOAD_OK=1 を付けて再実行／push する")
            return 3
        ans = input(f"WARN {len(rep.warns)}件を確認しました。アップロードを続けますか？ [yes/N] ").strip().lower()
        if ans != "yes":
            print("結果: HOLD 承認なし。push しない")
            return 3
        save_baseline(repo, baseline_data, new_keys, "tty-yes")
        print("結果: PASS（WARN確認済み・baselineに記録）")
        return 0
    print(f"結果: PASS (WARN {len(rep.warns)}件)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
