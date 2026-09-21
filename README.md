# ghcheck — GitHubへ push する前の秘密情報チェック（学習つき）

push の前に「Private か・100MB超が無いか・鍵や秘密が混ざっていないか」を機械的に検査し、
確定できない疑いは **人が確認してから** push させるツールです。
一度確認した疑いは記録され、二度と聞かれません。あなたが実際に使っている鍵を学習させると、
その値や同じ形の値がコードに混入した瞬間に止まります。

AI コーディングエージェントと相性がよいように作っています。ファイルの中身を読むのはこのツール（トークン0）で、
エージェントが読むのは集約された数行だけです。

## 特徴

- **5つの検査**: リポジトリ可視性（PRIVATE 以外は FAIL）／100MB超ファイルと履歴の blob／危険なファイル名（.env・秘密鍵・cookie 等）／既知サービスの鍵パターン22種／禁止ディレクトリ
- **疑いは WARN**: 32/40/64桁 hex、base64 風、高エントロピー文字列、鍵の分割連結、URL 埋め込み認証など。止めないが確認を求める
- **確認ゲート**: `--confirm` で新しい WARN があれば HOLD（exit 3）。承認は `GITHUB_UPLOAD_OK=1 git push`。承認内容は `.github_upload_check.baseline.json` に誰が・いつ・何を、として残る
- **pre-push hook**: `--install-hook` で `git push` 自体が検査になる
- **学習**: `--learn-secret file:line` で検出を本物と確定、`--learn-env` / `--learn-file .env` で使用中の鍵を取り込む。値の **HMAC 指紋**・**形**（接頭辞＋長さ）・**代入先の変数名** を覚える。平文は保存しない
- **学習データは暗号化＋分散**: AES-256-CBC + HMAC で暗号化し、乱数パッドで XOR 分割した2断片を別々の場所に置く。鍵は macOS Keychain。鍵＋両断片が揃わないと復号できない
- **依存なし**: Python 3.9+ 標準ライブラリと `git`。可視性確認に `gh`、暗号化に `openssl`、鍵保管に macOS の `security`（無い環境ではファイル鍵に退避）

## インストール

```bash
git clone https://github.com/hikutiki/ghcheck.git ~/ghcheck
export PATH="$HOME/ghcheck:$PATH"    # ghcheck-dir / ghcheck-commit を使う場合
```

## 使い方

```bash
ghcheck-commit                 # これから push する差分だけ検査（日常用）
ghcheck-commit --staged        # commit 前のステージ分
ghcheck-dir src lib            # ディレクトリ内の追跡ファイルを全件検査（初回棚卸し用）
ghcheck-dir -- --history       # 履歴の 100MB 超 blob も走査

python3 github_upload_check.py --install-hook   # git push 時に自動実行
GITHUB_UPLOAD_OK=1 git push                     # WARN を確認して承認した上で push
```

### 判定

| 結果 | exit | 意味 | 次の動作 |
|---|---|---|---|
| PASS | 0 | FAIL も新しい WARN もない | push してよい |
| HOLD | 3 | 新しい WARN があり未承認 | 一覧を見て `GITHUB_UPLOAD_OK=1 git push`（対話端末なら `yes`） |
| FAIL | 1 | Private 以外・100MB超・秘密・危険ファイル名・禁止 dir | 直す。承知で通すなら `--warn-only` |
| 実行不能 | 2 | git でない・規則 JSON 不正 | 設定を直す |

### 学習させる

```bash
python3 github_upload_check.py --learn-env --learn-file .env   # 使っている鍵を最初に教える
python3 github_upload_check.py --learn-secret src/config.py:12 # 検出が本物だったとき
python3 github_upload_check.py --learn-status                  # 件数と保存場所
python3 github_upload_check.py --forget-all                    # 消去
```

以後、学習した値の再出現は FAIL、同じ形の値や同じ変数名への代入は WARN になります。

学習データの場所（環境変数で変更可）:

| 何 | 場所 |
|---|---|
| 鍵 | macOS Keychain（service `github_upload_check`）。無ければ `$GHCHECK_STORE_DIR/key` |
| 断片1 | `$GHCHECK_STORE_DIR/learned.shard1`（既定 `~/.config/github_upload_check/`） |
| 断片2 | `$GHCHECK_SHARD2_DIR/learned.shard2`（既定 `~/Library/Application Support/github_upload_check/`） |

## 規則のカスタマイズ

3層で合成されます（リストは追記、閾値は上書き）。

1. 同梱の `github_upload_check.rules.json` — 共通既定
2. リポジトリ直下の `.ghcheck.json` — そのリポジトリ固有（自動読込）。`.ghcheck.example.json` を参照
3. `--rules my.json` — 案件ごとの追加

```json
{
  "forbid_dirs": ["notes", "private"],
  "ignore_line_keywords": ["notion.so", "revision"],
  "downgrade_globs": ["*/tests/*"],
  "secret_patterns": [{"label": "社内トークン", "regex": "MYCORP-[A-Z0-9]{32}"}]
}
```

- `secret_patterns` / `dangerous_names` / `forbid_dirs` → FAIL
- `warn_patterns` / `dangerous_warn` / `entropy` → WARN
- `ignore_line_keywords` を含む行はハッシュ等とみなして疑い判定から除外
- `downgrade_globs` に一致する path（tests 等）では秘密パターンの FAIL を WARN に格下げ

## 誤検出について

初回は一時パス・ハッシュ・テスト用ダミー値が疑いとして出ます。手元の実測では 451 ファイルのディレクトリで
339件 → 除外語を数個足して 3件 → `--accept` 後 0件 でした。以降は差分の新規分だけになります。

## 限界

- パターン走査です。PASS は「機密なし」の証明ではありません
- 指紋は完全一致のみ。1文字でも違えば形か規則でしか拾えません
- 形は接頭辞のある値だけ学びます。接頭辞の無い乱数値は指紋のみ
- 履歴の走査は 100MB 超 blob だけです。過去 commit の秘密は別ツール（git filter-repo 等）で対処してください

## ライセンス

MIT
