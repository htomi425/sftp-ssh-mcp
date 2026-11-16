# 依存関係更新と検証用パッケージの固定

## ルートの互換更新

`.github/workflows/dependency-review.yml` は `refactor/core` でのみ動作する。
更新候補を実行するジョブは `contents: read` とし、checkoutの認証情報を残さない。
候補の `npm ci`、通常テスト、本番依存のHigh以上の監査ゲートを通過した場合に限り、ロックファイルをartifactへ保存する。

自動反映は別の新しいrunnerで行う。このジョブだけが `contents: write` を持つ。
元のcommitをcheckoutし、候補の依存関係はインストール・実行しない。
Node標準ライブラリだけの検査で、ファイルの種類・サイズ、JSON形式、プロジェクト情報と直接依存宣言の不変性、npm公式registryのHTTPS tarball、SHA-512 integrityを確認する。
反映するのは `package-lock.json` だけ。ブランチ先端が変わっていたら反映を見送り、pushもforceしない。

これは候補依存コードと書込み認証情報を同じrunnerに置かないための対策であり、npmパッケージ自体が無害であることを証明するものではない。
読み取りジョブにはGitHubの実行時tokenやartifactサービスへのアクセスがある。外部秘密情報は渡さない。
本番依存の監査ゲートと別に、全依存の監査JSONもレポートとして保存する。

GitHub Actions自身のtokenで作った更新commitは、通常、後続のpush/PRワークフローを起動しない。
そのcommitでは候補ジョブの通常テストを確認できるが、Node.js 22、OpenSSH統合、OAuthの全ジョブの再実行を意味しない。
取り込み前には最終ロックファイルを含む先端で通常CIの成功を確認する。

## Cloudflareの隔離検証

`integrations/cloudflare/validation/package.json` の直接依存を完全なバージョンに固定し、同じディレクトリの `package-lock.json` を管理する。
通常CIと手動検証は `npm ci --ignore-scripts` を使う。
Miniflareが固定している推移依存の `sharp` と `undici` は、既知の脆弱性に対応する修正版へ `overrides` で固定する。
更新時はロックファイルをnpmで再生成し、全6種のOAuth/workerd検証を通す。手編集でintegrityを作らない。
High以上の依存脆弱性は検証ジョブを失敗させる。

バージョン固定は再現性の対策であり、将来の脆弱性が発生しないという意味ではない。
監査データベースの更新やMiniflare側の依存更新に合わせて、overrideの必要性と互換性を再評価する。

## 実環境への移行

現在はGitHub Actionsの隔離環境で検証する。
実CT・実IdP・実クライアントへの接続やデプロイは保留。
移行前に、残る指摘、受入条件、操作範囲を確認する。Draft解除とmainへの取り込みも別途判断する。
