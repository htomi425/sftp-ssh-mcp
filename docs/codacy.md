# Codacy導入・解析の使い方

公式の [codacy/codacy-skills](https://github.com/codacy/codacy-skills/tree/caa5d6f7f1f7261e469b2de7951707c553b23ee4) を参照して導入した。

| 経路 | 用途 | 設定 |
| --- | --- | --- |
| Codacy Cloud / GitHub App | PRの品質チェック | [PR #10のCodacy画面](https://app.codacy.com/gh/htomi425/sftp-ssh-mcp/pull-requests/10)で管理 |
| Codacy Analysis CLI | 広いルールセットでの追加解析 | `.codacy/codacy.config.json` |
| Codacy local analysis (manual) | CLI解析の再現とレポート保存 | `.github/workflows/codacy-onboarding.yml`、手動実行のみ |

ローカル設定をコミットしてもCloudへ自動適用されない。Cloudへの一括インポートは行っていない。
通常のpushでCLIの重いジョブを追加しない。既存CIの文書専用変更時のスキップ方針は継続する。

## 初回検証

対象の実行コードは `3351df8d71134bed7c496c9d330d6e16ade61ac3`。

- [通常CI #429](https://github.com/htomi425/sftp-ssh-mcp/actions/runs/43853689697): Node.js 22/24、通常テスト122件成功・失敗0、実SSH/SFTP統合7件成功、Cloudflare OAuth検証成功。
- [Alpine検証](https://github.com/htomi425/sftp-ssh-mcp/actions/runs/43853916307): Alpine 3.24.4 / Node.js 24.22.3、1 CPU、512 MiBで同じテストが成功。実CTではなく隔離コンテナ。
- [Codacy CLI検証](https://github.com/htomi425/sftp-ssh-mcp/actions/runs/43853689049): CLI 0.29.1。設定済み8エンジンが実行され、未導入エンジン0、解析エラー0。
- 同コミットのCodacy Cloudチェックは成功。これはCloudで選択されたルールとPR差分の品質ゲートの結果であり、下記の広いローカル解析の全指摘が解消したことを示さない。

| CLIエンジン | 指摘数 |
| --- | ---: |
| jackson | 0 |
| markdownlint | 3 |
| Trivy | 0 |
| Semgrep | 10 |
| spectral | 0 |
| ESLint9 | 809 |
| Checkov | 0 |
| Lizard | 19 |
| 合計 | 841 |

841件は未トリアージの静的解析指摘で、841件の確認済みバグという意味ではない。
Security分類はCritical相当20件、High 47件を含む。テストの意図的な入力やAPI用途もあり、個別のソース確認が必要。
手動Actionsは現段階では指摘の収集を目的とし、指摘があるだけでは失敗させない。
エンジン未実行、未導入、例外、部分解析は失敗として扱う。`toolResults`が空の結果を合格にしない。

## 設定と解析範囲

本体、Cloudflare連携、テスト、設定ファイルを解析する。
依存の実体 `node_modules/**`、生成物 `build/**`、`coverage/**`、`.git/**`、解析器の作業領域 `.codacy/**` は除外する。
テスト全体やSecurityカテゴリを一括除外していない。

初回の例外対応:

1. PEMヘッダー除去の正規表現を秘密鍵本体と誤認したルールは、その行だけに理由付きの `nosemgrep` を付けた。秘密鍵の値は環境バインディングから受け取る。
2. Miniflareのテスト環境へ変数を渡す記述を固定トークンと誤認したルールは、該当するバインディング行だけに理由を記録した。テスト用トークンと同意署名鍵は実行ごとの乱数に変更。
3. ローカルの `ESLint9_security-node_detect-unhandled-async-errors` は、実コードでAST例外を発生させ同プラグインの22ルールをスキップしたため、互換性対応としてこの1ルールだけ外した。残り21ルールを維持する。このルールの検査は未実施という制約が残り、CLIまたはプラグイン修正後に再評価する。
4. SemgrepがCI内のGitHub式をシェルとして解析できなかった箇所は、式を環境変数経由で渡す構成に変更した。ルール自体は維持した。

## ローカルで再実行（シェル例）

```sh
npm ci
npm install --global @codacy/analysis-cli@0.29.1
mkdir -p .codacy/tmp
codacy-analysis analyze --inspect --output-format json --output .codacy/tmp/capabilities.json
codacy-analysis analyze --install-dependencies --output-format json --output .codacy/tmp/baseline.json
codacy-analysis analyze --fail-if-missing --output-format json --output .codacy/tmp/results.json
```

`--inspect`、`--install-dependencies`、`--fail-if-missing` は併用せず別々に実行する。
終了コード1は指摘あり、2は実行上の問題を示す。終了コードだけでなく `errors`、`capability.unavailable`、`toolResults` を確認する。
保存済み設定の互換性例外を維持するため、無条件の `init --auto` や設定再生成は避ける。

Cloud CLIを使用する場合は `@codacy/codacy-cloud-cli@1.15.0` と `codacy login` を利用する。
認証情報をソースやチャットへ貼らず、CLIの認証保管場所または実行環境の秘密情報として扱う。
Cloud設定のインポートや組織標準の解除は、対象と変更内容を確認してから行う。

## 依存関係に関する追加対応（2026-11-17）

初回CLIレポートのSecurity分類67件は、ソースと呼出し元を確認した結果、61件を現行の対応経路では対応不要、6件を追加確認対象とした。
これは初回スナップショットの判定であり、全841件の解消を意味しない。

6件の対象はルートの4つのバージョン範囲と、検証用のesbuild・Miniflare。
ルートは互換更新の方針を維持し、候補依存を実行するジョブと書込み権限を持つ反映ジョブを分離した。
検証用依存は完全バージョンとロックファイルへ固定し、npm ciへ変更した。
ルールの一括無効化やCloud上の指摘の一括無視は行っていない。
静的解析がバージョン範囲そのものを検出する場合、ルートの同じ指摘は残り得る。

固定した検証用ロックファイルに対して、Cloud解析はsharp 0.35.2とundici 7.28.0に合計25件の既知脆弱性を検出した。
sharp 0.35.5とundici 7.30.1へoverrideし、npmでロックを再生成した。
[隔離検証](https://github.com/htomi425/sftp-ssh-mcp/actions/runs/43933286363)で全6種のOAuth/workerd検証が成功した。
通常CIには検証用依存のHigh以上を拒否する監査ゲートも追加した。

権限、更新手順、残る制約は[依存関係更新](./dependency-updates.md)を参照。
