# Cloudflare Access と MCP OAuth のセッション設計

初回Cloudflare構成の設計。実装の基準は `b3b8fe8`。公開MCPリソースは `https://ssh-mcp.hg0.me/mcp`。本番のAccessアプリと認可Workerのホスト名は導入時に決める。

## ブラウザログインと認可

Accessアプリの保護範囲を認可Workerの `/authorize` に限定し、同意画面のGETとPOSTを保護する。MCPリソース、OAuthメタデータ、トークン交換、クライアント登録は、ブラウザのAccessセッションを持たないMCPクライアントから到達できるようにする。MCPリソースは既存のOAuth Bearer検証を必須とする。

認可Workerは `Cf-Access-Jwt-Assertion` の署名、固定のチーム発行元とアプリのAudience、期限、ユーザーの `sub` をGETとPOSTで検証する。鍵取得先は設定済みチームドメインの公開鍵エンドポイントに固定し、鍵更新に対応する。HTTP経路の実ユーザー認証に使えるAccessアプリケーショントークンを受け付け、サービス認証やユーザー識別子のないトークンを拒否する。既存の汎用セッションCookieアダプターは別のIdPで利用できる。

同意と付与の主体はAccessの発行元と `sub` の組とする。Node側のSSH接続先許可リストでも同じ組を照合する。同意フォームを発行した主体または失効世代がPOST時に変わっていれば拒否し、同意を最初からやり直す。付与には主体、有効期限、失効世代を記録する。

## 期限

| 対象 | 初回の設定値と挙動 |
| --- | --- |
| Accessのブラウザセッション | 専用Accessアプリの有効期間は3日を候補とする。実際の発行期限は署名を確認したアプリケーショントークンの `exp` を使用する。 |
| MCP OAuthの付与・更新トークン | 同意承認から最長3日、かつ承認時のAccessトークンの `exp` まで。更新トークンは交換ごとにローテーションし、付与の絶対期限は固定する。 |
| MCP OAuthのアクセストークン | 最長10分、かつ付与の絶対期限まで。期限を過ぎた付与や、残り時間が採用済みProvider 1.2.4で発行可能な最短TTLを下回る付与は `invalid_grant` で再認可を求める。 |

認可コード交換時に残り時間からProviderの固定更新TTLを設定する。コード交換・更新時とリソースのアクセストークン検証時に保存済み絶対期限を照合し、時計の丸めや処理時間による延長を防ぐ。固定更新TTLとし、アイドル更新TTLは設定しない。付与が満了したらエンドユーザーがOAuth同意からやり直す。Access側のSSOが有効な場合は、IdPの資格情報の入力が省略されることがある。

## 失効とユーザー切替

Accessのログアウトはブラウザ側のセッションに作用する。発行済みMCPトークンを止める操作にはMCP側の失効を使う。利用者が接続を解除する場合は、クライアントが対応していればOAuthトークン失効を利用する。管理者は、ユーザーの無効化が必要な場合、MCP側でその主体を停止して失効世代を進め、AccessとIdP側の権限も取り消す。利用を再許可する場合は停止を解除し、新しい同意から開始する。

管理用の停止状態と世代は認可WorkerのプライベートなDurable Objectで主体ごとに管理する。認可コード交換、更新、MCPリクエストのトークン検証で毎回確認し、停止後の新しい処理を拒否する。ストアへの照会に失敗した場合はトークン発行とSSHへの転送を止める。Provider側の付与の削除も行い、停止の反映はKVの伝播を待たず専用の状態照会で行う。失効前にNodeへ転送済みの処理は、既存のリクエスト期限と切断処理に従う。

別のユーザーで接続する場合は、旧接続を解除し、切り替えたAccessアカウントで同意を取り直す。ブラウザのアカウント切替後も、旧トークンが表すユーザーは旧主体のまま。既存の同意フォームを別ユーザーで送信した場合は付与を作らない。

## 分離環境での完了条件

- Accessの期限切れ、署名・発行元・Audienceの不一致、サービス認証を拒否する。鍵ローテーションで有効な新しい鍵を取得できる。
- ブラウザセッションなしでMCP OAuthのメタデータ取得、登録、コード交換、トークン更新ができる。MCPリソースは適切なBearerチャレンジを返す。
- 承認時のAccess期限が短い場合、コード交換が遅れた場合、更新の最短TTL未満の場合を確認する。連続更新でも付与の絶対期限が延びず、失効・期限切れでSSH接続を開始しない。
- Aで表示した同意フォームをBで送ると拒否される。Bでやり直すとBの接続先だけが許可され、AのトークンからBの接続先は利用できない。
- MCP側の主体停止後に、発行済みアクセストークンと更新トークンを異なるWorkerインスタンスから使って拒否を確認する。ストア障害時にSSHが開始されないこと、再許可後も旧世代が無効なことを確認する。
- 最後に実IdPとChatGPTでログイン、更新、期限切れ後の再認可、接続解除とユーザー切替の挙動を確認する。

## 参照

- [Cloudflare Accessのセッション管理](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/)
- [AccessのJWT検証](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Accessのアプリケーションパス](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/)
- [Workers OAuth Providerのトークン交換と有効期間](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/authorization-server.md)
