# SFTP-SSH MCP Server — 日本語README

[English README](./README.md) | [Cloudflare連携の詳細（英語）](./integrations/cloudflare/README.md)

> **開発状況:** この文書は `refactor/core` ブランチの実装に対応します。OAuth/Cloudflare連携は隔離環境でテスト中であり、本番環境へのデプロイや実際のIdP連携が完成したことを意味しません。`main` ブランチの仕様とは異なる場合があります。

## 概要

SSHでリモートホストのコマンドを実行し、SFTPでファイル操作を行う [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) サーバーです。MCPクライアントから操作する対象はLinux/Windowsなど、SSH/SFTPサーバーが動作するシステムです。

- **stdio（標準）:** ローカルのMCPクライアントが子プロセスとして起動。CloudflareやOAuthは不要です。
- **Streamable HTTP（明示的に有効化）:** ループバックアドレスにのみ待受。静的Bearer認証、または署名付きゲートウェイアサーション認証を選択できます。Node.jsのHTTPモード単体はOAuth認可サーバーではありません。
- **複数のSSH接続先:** `SSH_MCP_TARGETS` で最大32件の名前付き接続先を定義できます。HTTP利用者の接続先権限はサーバー側の許可リストで制限します。
- **SSHホスト鍵検証:** 接続先ホスト鍵のSHA-256フィンガープリント固定を必須とします。

## 必要な環境とビルド

Node.js 22/24でCIを実行しています。SSH/SFTPを利用するリモートホストと、実行するコマンドに必要な権限を用意してください。

```sh
git clone https://github.com/htomi425/sftp-ssh-mcp.git
cd sftp-ssh-mcp
git switch refactor/core
npm ci
npm run build
npm test
```

このブランチはまだ開発中です。以下の使用例では公開済みnpmパッケージの内容と混同しないよう、ローカルでビルドした `build/index.js` を起動します。

## まずstdioで使う

従来のCLIは `--host`、`--user`、`--port`、`--password` または `--key` を受け付けます。さらに、接続先SSHホスト鍵のSHA-256フィンガープリントを `SSH_HOST_KEY_SHA256` に設定する必要があります。

```sh
SSH_HOST_KEY_SHA256="<64桁のSHA-256十六進数>" \
node build/index.js --host=192.0.2.10 --port=22 --user=example --key=/path/to/private_key
```

上記IPアドレスとパスは例です。フィンガープリントは**接続先管理者が信頼できる経路で確認した値**を使用してください。`ssh-keygen -lf` 等が表示する `SHA256:...` のBase64形式は、そのままではこの実装に指定できません。必要なのは**64桁の十六進数**です。鍵を初めて受け取った通信経路だけを信頼して固定しないでください。

GUI型MCPクライアントへの設定例（`command` とファイルパスは環境に合わせて変更）:

```json
{
  "mcpServers": {
    "sftp-ssh-mcp": {
      "command": "node",
      "args": [
        "/absolute/path/to/sftp-ssh-mcp/build/index.js",
        "--host=192.0.2.10",
        "--user=example",
        "--key=/absolute/path/to/private_key"
      ],
      "env": {
        "SSH_HOST_KEY_SHA256": "<64桁のSHA-256十六進数>"
      }
    }
  }
}
```

パスワード認証も利用できますが、CLI引数に平文パスワードを含めると、プロセス一覧やクライアント設定から露出する恐れがあります。鍵認証と適切なファイル権限を推奨します。

## 複数の接続先

`SSH_MCP_TARGETS` にJSONオブジェクトを設定すると、従来のCLI接続先設定ではなくこちらを使用します。

```json
{
  "alpha": {
    "host": "192.0.2.10",
    "port": 22,
    "user": "operator",
    "key": "/secure/path/id_ed25519",
    "hostKeySha256": "<64桁のSHA-256十六進数>"
  },
  "beta": {
    "host": "192.0.2.11",
    "user": "operator",
    "key": "/secure/path/id_ed25519_beta",
    "hostKeySha256": "<64桁のSHA-256十六進数>"
  }
}
```

CLI側でなく環境変数としてこのJSONを渡してください。各接続先には `host`、`user`、`hostKeySha256` と、`password` または `key` の**いずれか一方のみ**が必要です。 `port` は省略時22です。複数の接続先で `default` がない場合は、ツール呼び出しで `target` を指定してください。

## 利用できるMCPツール

| ツール | 機能 | stdio | HTTP |
|---|---|---|---|
| `exec` | SSHコマンド実行 | 利用可能 | 許可された接続先のみ |
| `sftp_list` | リモートディレクトリ一覧 | 利用可能 | 許可された接続先のみ |
| `sftp_upload` | MCPサーバー側ローカルファイルをリモートへアップロード | 利用可能 | **無効** |
| `sftp_download` | リモートファイルをMCPサーバー側ローカルへダウンロード | 利用可能 | **無効** |

HTTPのアップロード・ダウンロードは、サーバー上の任意ファイルへアクセスできる危険を避けるため拒否されます。ツール一覧に表示されても、HTTP経由で実行可能という意味ではありません。SFTPアップロード時には既存ファイルを上書きしない処理があります。リソース制限の詳細は [resource-limits.md](./docs/resource-limits.md) を参照してください。

## Streamable HTTP（任意・開発用）

HTTPを使う場合は、まず名前付き接続先 `SSH_MCP_TARGETS` を定義してください。

```sh
export SSH_MCP_TARGETS='<上のJSONを1行にしたもの>'
export SSH_MCP_TRANSPORT=http
export SSH_MCP_HTTP_AUTH_MODE=static
export SSH_MCP_HTTP_CREDENTIALS='[{"id":"operator","token":"<32文字以上のランダムなURL-safeトークン>","targets":["alpha"]}]'
node build/index.js
```

既定の待受先は `127.0.0.1:3000`、MCPエンドポイントは `/mcp` です。`SSH_MCP_HTTP_HOST` は `127.0.0.1`、`::1`、`localhost` のみ受け付けます。静的Bearer方式は**OAuthではありません**。外部公開する場合は、信頼できるTLS終端・認証・プライベート経路を別途設計してください。現時点では一般公開を推奨しません。

主要設定:

| 環境変数 | 内容 |
|---|---|
| `SSH_MCP_TRANSPORT` | `stdio`（既定）または `http` |
| `SSH_MCP_HTTP_AUTH_MODE` | `static`（既定）または `gateway` |
| `SSH_MCP_HTTP_CREDENTIALS` | 静的認証時の利用者ID・Bearerトークン・許可先 |
| `SSH_MCP_HTTP_HOST` / `SSH_MCP_HTTP_PORT` | HTTP待受（既定 `127.0.0.1:3000`） |
| `SSH_MCP_HTTP_MAX_BODY_BYTES` | HTTP要求本文の上限（既定1MiB） |
| `SSH_MCP_HTTP_MAX_REQUESTS` | 同時HTTP要求上限（既定8） |
| `SSH_MCP_HTTP_REQUEST_TIMEOUT_MS` | HTTP要求タイムアウト（既定120000ms） |
| `SSH_MCP_MAX_CONNECTIONS` | 同時SSH接続数の上限（既定2） |
| `SSH_MCP_MAX_TRANSFER_BYTES` | SFTP転送サイズ上限（既定64MiB） |
| `SSH_MCP_TRANSFER_TIMEOUT_MS` | SFTP転送タイムアウト（既定120000ms） |

### Gateway認証とCloudflare OAuth

`SSH_MCP_HTTP_AUTH_MODE=gateway` では、Node.js側がEd25519で署名された短命のゲートウェイアサーションを検証します。署名・発行者・対象・HTTPメソッド・パス・要求本文ハッシュ・再利用防止を検証した後、`SSH_MCP_IDENTITY_TARGETS` に設定した `issuer` と `subject` から接続先権限を解決します。

Node.js側に必要な主な変数は `SSH_MCP_GATEWAY_ISSUER`、`SSH_MCP_GATEWAY_AUDIENCE`、`SSH_MCP_GATEWAY_PUBLIC_KEY_PEM`、`SSH_MCP_IDENTITY_TARGETS` です。未検証のユーザー情報ヘッダーやクライアントが指定する接続先許可リストを信頼しません。

Cloudflare側は独立したOAuth Authorization WorkerとResource Workerを使用する設計です。Miniflare/workerdの隔離テストで、Discovery、クライアント登録、PKCE、明示的同意、OAuthアクセストークン検証、Service Binding、ゲートウェイ署名、およびテスト用Node.jsオリジンまでの検証を実施しています。ただし、**実際のIdPログイン・セッション失効、本番Workerの秘密情報、実際のCloudflare Tunnel経路、実ブラウザークライアントによる本番接続は未完成・未検証**です。

詳しくは [Cloudflare統合README（英語）](./integrations/cloudflare/README.md) と [HTTP/OAuth設計（英語）](./docs/http-oauth-architecture.md) を参照してください。

## セキュリティ上の注意

- リモートコマンドはSSH接続ユーザーの権限で実行されます。最小権限の専用ユーザーを推奨します。
- SSHホスト鍵のフィンガープリントを事前に検証し、接続先ごとに固定してください。
- 秘密鍵・Bearerトークン・OAuthの署名鍵をGitやログへ保存しないでください。
- HTTP Gateway認証の再利用防止キャッシュは単一Node.jsプロセス内に存在します。複数インスタンスでは共有の原子的な再利用防止ストアが必要です。
- OAuthを利用した本番公開を、このブランチのCI成功だけで安全と判断しないでください。

## 開発・検証

```sh
npm ci
npm test
```

CIではNode.js 22/24のビルド・単体テスト、隔離したOpenSSH統合テスト、Cloudflare OAuth Providerの隔離統合テストなどを実施します。検証用の固定トークンや鍵は本番に使用しないでください。

本書は開発中ブランチの現状に合わせて更新していきます。実装上の仕様と差異がある場合は、該当ブランチのソースコードとテスト結果を優先して確認してください。

## CIの変更検出

GitHub ActionsはPR更新または`main`へのpush時に変更ファイルを確認し、`README.md`、`README.ja.md`、`docs/*.md`、`integrations/cloudflare/README.md` **だけ**が変更された場合、ビルドと統合テストをスキップします。変更検出ジョブ自体は実行されます。PRの更新分だけを安全に比較できない場合はPR全体を判定します。`refactor/core`へのpushによるCIの二重起動は行いません。ソースコード、テスト、依存関係、ワークフロー設定、未分類のファイルが1つでも変更された場合や変更判定に失敗した場合は、通常のCIを実行します。GitHubのブランチ保護で個別テストジョブが必須Checkとして設定されている場合、スキップがマージ判定に与える影響を別途確認してください。
