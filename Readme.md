# SilentGuard 基本設計書（v1.0）

## 1. システム概要

SilentGuardは、Windows環境において新規作成・変更されたファイルをリアルタイムで監視し、外部スキャンエンジンを用いてウイルスチェックおよび隔離・削除を行う軽量セキュリティツールである。主な利用シーンは、企業内部における軽量の監視用途を想定している。

---

## 2. 開発背景・目的

- Windows Defenderのみに依存しない柔軟なスキャン運用の実現  
- 軽量・非侵入型の常駐監視により業務アプリとの干渉を最小化  
- 将来的な買収を見据えたシンプルな構成と外部依存最小化

---

## 3. システム構成（概要）

- **監視方式：**  
  - ETW（Event Tracing for Windows）によるカーネルレベルのファイルI/O監視  
  - FileSystemWatcherによるファイル作成・変更監視

- **スキャンエンジン：**  
  - 外部実行可能ファイル（`config.json`にて指定）

- **ログ出力：**  
  - 指定ディレクトリに時系列のテキストログを出力（SHA256、脅威判定、対処内容）

---

## 4. 処理フロー

1. **システム起動**  
   - `config.json` 読み込み  
   - ログ／隔離フォルダ作成  
   - 監視プロセス（ETW、FSW、イベント処理）を非同期起動

2. **ファイル検知**  
   - `.exe`, `.dll` 等の拡張子を持つファイルの作成・変更を検出  
   - キューにファイルパスとPIDを登録

3. **スキャン＆処理**  
   - Engine1でスキャン  
   - 脅威検知時はプロセス強制終了 → 隔離  
   - 隔離後、Engine2で再スキャン → 脅威ありなら削除  
   - 各ステップでログ出力

---

## 5. 対象ファイル拡張子

以下の拡張子を「危険ファイル候補」として処理対象とする：
.exe, .dll, .sys, .bat, .cmd, .txt, .ps1, .vbs, .js, .py, .wsf, .msi, .scr, .com

---

## 6. ディレクトリ構成

| パス | 用途 |
|------|------|
| `C:\ProgramData\SilentGuard\Quarantine\` | 隔離ファイル保管先 |
| `C:\ProgramData\SilentGuard\log\` | スキャンログ保存先 |
| `config.json` | スキャンエンジンのパス指定用（`scanEngine1`, `scanEngine2`） |

---

## 7. 外部連携（スキャンエンジン）

- **入力：**  
  引数 `-Scan -ScanType 3 -File "path"` を指定して外部プロセス実行

- **出力：**  
  標準出力に「Threat found」や「脅威が見つかりました」の文字列で判定

---

## 8. ログ仕様

- **出力例：**
2025-06-13 12:30:15 | C:\Users\xxx\evil.exe | SHA256=abc123... | Threat=有 | Action=Quarantine

---

## 9. 非機能要件

- メモリ使用量：常駐時 約4MB  
- 処理遅延：スキャン・ログ出力まで1〜2秒以内

## ライセンス
このプロジェクトは [Apache License 2.0](LICENSE) のもとで公開しています。
