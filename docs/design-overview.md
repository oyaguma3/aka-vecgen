# aka-only-server 設計概要

- 状態: フェーズ1〜3 の実装に合わせて更新済み（2026-10-04）
- 対象: aka-only-server 本体。システム全体の構成もここに記載する。
- 関連: BFF / Web GUI 側の設計概要は web-gui-for-aka-only-server リポジトリの `docs/design-overview.md` を参照。

旧実装（PostgreSQL + Gin + IP許可リスト）は流用せず、コードとドキュメントを削除したうえで全面的に作り直した。

## 1. 目的と範囲

指定した IMSI に対して Milenage による AKA 認証ベクターを払い出す API サーバー。EAP-AKA / EAP-AKA' の RADIUS サーバーなどがクライアントになる。

- 提供するのは API のみ。GUI は持たず、特定の GUI 実装に依存しない。
- 個人利用・検証用途を想定し、VPS に `git clone` して `docker compose up` で起動できる手軽さを優先する。
- 加入者情報・鍵情報は平文保存または最低限の保護とする。

対象外: OAuth2.0、NRF 連携、Milenage 以外のアルゴリズム、EPS-AKA（KASME）、5G-AKA（Kausf / XRES*）。

## 2. 全体構成

```
[AVクライアント]                      [ブラウザ]
 (EAP-AKAサーバー等)                      │ HTTPS（VPN 越し）
     │                                    ▼
     │ mTLS または平文HTTP        web-gui-for-aka-only-server
     │                           BFF + Web GUI
     │                                    │ mTLS（管理用証明書）
     ▼                                    ▼
   認証ベクターAPI                      管理API
   ───────────── aka-only-server ─────────────
                          │
                    Valkey（永続化）
```

| リポジトリ | 責務 |
|---|---|
| aka-only-server | 認証ベクターAPI、管理API、Milenage / SQN 処理、加入者・クライアントのデータ |
| web-gui-for-aka-only-server | BFF、Web GUI、ログインアカウントと権限。aka-only-server の管理 GUI 実装の1つ |

2つのリポジトリは同一ホストでも別ホストでも動かせるようにする。両者の接点は管理API（mTLS）だけとする。

## 3. 技術方針

- 言語: Go 1.27.3。
- 標準ライブラリを優先する。HTTP は `net/http`、TLS は `crypto/tls`、JSON は `encoding/json/v2`、ログは `log/slog`、設定は環境変数（`os.Getenv`）。
- 外部依存は次に限る。
  - `github.com/wmnsk/milenage`: Milenage 計算
  - `github.com/valkey-io/valkey-go`: Valkey クライアント
- プロジェクト全体で認める例外は、これに `golang.org/x/crypto`（BFF 側のパスワードハッシュ）を加えた3つとする。
- module パス: `github.com/oyaguma3/aka-only-server`
- データベース: Valkey。永続化して使う。
- 配備: Docker Compose。ホスト OS は Debian を主対象とし、Ubuntu Server でも動く見込み。

## 4. リスナー構成

| リスナー | 用途 | 認証 | 既定 |
|---|---|---|---|
| AV / mTLS | 認証ベクターAPI | クライアント証明書必須。登録済み証明書のみ許可 | 有効 |
| AV / 平文HTTP | 認証ベクターAPI | なし（匿名） | 無効 |
| 管理 / mTLS | 管理API | クライアント証明書必須。静的設定された証明書のみ許可 | 管理クライアントを設定した場合だけ有効 |

- TLS は Go アプリ自身で終端する。リバースプロキシは置かない。
- AV / mTLS では、証明書なしの接続と未登録証明書の接続をどちらも拒否する。
- AV / 平文HTTP は、AKA-RADIUS サーバーや TS.43 Entitlement Server などの AV 取得クライアントを同一ホストに併存させるケースのためのもの。CK/IK が平文で流れるため既定で無効とし、有効にする場合はバインド先をループバックや Docker 内部ネットワークに限定する。
- AV 用と管理用でサーバー証明書・ポートを分ける。

## 5. 認証ベクターAPI

### 5.1 ベース仕様

3GPP TS 29.503 Nudm_UEAuthentication の GenerateAv（HSS 連携用）をベースにする。

```
POST /nudm-ueau/v1/{supi}/hss-security-information/{hssAuthType}/generate-av
```

- `supi`: `imsi-<IMSI>` 形式。
- リクエスト（HssAuthenticationInfoRequest）: `hssAuthType`、`numOfRequestedVectors`（1〜5）、`resynchronizationInfo`（`rand` / `auts`）、`anId`。
- レスポンス（HssAuthenticationInfoResult）: `hssAuthenticationVectors`。
- エラーは ProblemDetails（`application/problem+json`）で返す。
- クライアントはトレースID を `X-Trace-ID` ヘッダーで渡せる。サーバーはそれを払い出しのログ（`trace_id`）に残し、応答の `X-Trace-ID` ヘッダーで返す。省略した場合や形式が違う場合は採番する。本PoCの vector-gateway が付けるトレースID と、1 回の認証の記録を突き合わせるため（管理API と同じ作法。認証ベクターAPI 0.2.0-draft、2026-10-12）。

パス、項目名、値の範囲は TS 29.503 v18.4.0 の OpenAPI 定義で確認した。詳細は `docs/openapi/av-api.yaml` に定義する。

### 5.2 対応する認証タイプ

| パスの hssAuthType | ボディの hssAuthType | 返すベクター | 内容 |
|---|---|---|---|
| `eap-aka` | `EAP_AKA` | AvImsGbaEapAka | RAND、XRES、AUTN、CK、IK |
| `umts-aka` | `UMTS_AKA` | AvImsGbaEapAka | RAND、XRES、AUTN、CK、IK |
| `eap-aka-prime` | `EAP_AKA_PRIME` | AvEapAkaPrime | RAND、XRES、AUTN、CK'、IK' |

- パスの `umts-aka` は TS 29.503 の列挙値にはない独自の拡張。
- これ以外の認証タイプはエラーとする。

### 5.3 AKA' の鍵導出

- CK' / IK' は TS 33.402 Annex A.2（RFC 5448 / RFC 9048）の KDF で導出する。
- Network Name は AVクライアントごとに設定できる。未設定のクライアントと平文HTTP の接続では `WLAN` を使う。
- リクエストに `anId` が入っていた場合もサーバー側の設定値を使い、不一致ならエラーにする。不一致の要求では SQN を進めない。
- AKA' では AMF の separation bit が 1 である必要がある。サーバーは加入者の AMF をそのまま使い、強制はしない。

### 5.4 再同期

`resynchronizationInfo` があれば再同期として扱う。AUTS の MAC-S を検証し、SQN_MS を取り出して加入者の SQN を置き換えたうえで、新しいベクターを生成する。

## 6. SQN 管理

SQN(48bit) = SEQ(43bit) || IND(5bit) とする。加算パターンは加入者ごとに指定する。

| タイプ | 1ベクター生成時の動作 |
|---|---|
| +1 | SQN 全体を 1 加算する（IND を意識しない単純カウンター） |
| +32 | SEQ を 1 加算し、IND は維持する |
| +33 | SEQ を 1 加算し、IND も 1 加算する。IND が 31 から 0 に回るときは SEQ に桁上げする（整数として 33 を加算するのと同じ） |

複数ベクター生成時は、バッチ内で IND を固定する（TS 33.102 Annex C の考え方）。

| タイプ | n 個生成時の動作 | SQN の総加算量 |
|---|---|---|
| +1 | 1個ごとに +1 | n |
| +32 | 1個ごとに +32 | 32n |
| +33 | 1個目は +33、2個目以降は +32（IND は1個目の値で固定） | 33 + 32(n−1) |

- SQN は Valkey に整数で保存する。
- 許可判定と SQN 更新は Lua スクリプトで1回の原子的な操作にまとめ、同時リクエストで同じ SQN が払い出されないようにする。

## 7. クライアント識別とアクセス制御

### 7.1 クライアント証明書（ピン留め方式）

- CA は立てない。クライアント証明書の PEM を管理API経由で登録し、SHA-256 フィンガープリントで照合する。自己署名証明書で足りる。
- TLS ハンドシェイクでは証明書の提示を必須とし、フィンガープリントが登録済みかつ有効なクライアントのものであることを確認する。有効期限も確認する。
- 登録・削除・無効化は再起動なしで即時に反映する。クライアントの情報はメモリに持たず、ハンドシェイクとリクエストのたびに Valkey で確認する。
- クライアントID は連番で発行し、再利用しない。

### 7.2 加入者ごとの許可判定

加入者は「許可クライアントID の集合」と「平文HTTP許可フラグ」を持つ。

| 接続 | 判定 |
|---|---|
| mTLS、登録済み証明書 | クライアントID が加入者の許可集合に含まれていれば許可 |
| mTLS、証明書なし・未登録証明書 | 接続を拒否 |
| 平文HTTP | 加入者の平文HTTP許可フラグが立っていれば許可 |

### 7.3 クライアント削除時の扱い

- クライアントID を再利用しないため、削除後に加入者の許可集合へ古い ID が残っても、別のクライアントに許可が引き継がれることはない。
- 残った ID の掃除は、削除処理の後に全加入者を走査して行う。安全性は掃除の完了に依存しない。
- 走査と削除は 500 加入者ずつパイプラインでまとめて送る。1万加入者での実測は約 0.3 秒（WSL2 上の Valkey 9.1、AOF を書き込みごとに同期する設定）。

## 8. 管理API

認証ベクターAPIとは別のポート・別のサーバー証明書で提供する。契約は OpenAPI で定義し、`docs/` に置く。

### 8.1 管理クライアント

- 管理クライアント（BFF など）は、環境変数 `AKA_ADMIN_CLIENTS` に「識別名=証明書の SHA-256 フィンガープリント」の形で静的に設定する。
- 管理クライアントが 1 つも設定されていなければ、管理API は起動しない。
- 管理クライアントは全権として扱う。ユーザーや権限の概念はサーバー側に持たない。
- 管理クライアントは操作者 ID を `X-Operator-Id` ヘッダーで渡し、サーバーはそれを監査ログに残す。省略した場合は管理クライアントの識別名だけが残る。
- 管理クライアントはトレースID を `X-Trace-ID` ヘッダーで渡せる。サーバーはそれをログと監査ログに残し、応答の `X-Trace-ID` ヘッダーで返す。省略した場合や形式（印字可能 ASCII 1〜64 文字）が違う場合は採番する（16 進 32 桁）。本PoC（eapaka-radius-server-poc）の Provisioning API と作法を揃え、BFF や統合API（eapaka-node-provisioner）の操作と、このサーバーの記録を突き合わせられるようにする（管理API 0.2.0）。

### 8.2 機能

| 分類 | 機能 |
|---|---|
| 加入者 | 一覧（ページング、IMSI 前方一致）、件数、個別取得、登録、変更、削除 |
| 加入者の鍵 | Ki / OPc の取得。通常の一覧・個別取得には含めず、専用の操作に分ける |
| 状態 | バージョン、起動日時、加入者数、クライアント数、AV用サーバー証明書の期限 |
| AVクライアント | 一覧、登録（証明書 PEM）、変更（名前、有効/無効、Network Name）、証明書の差し替え、削除 |
| AV用サーバー証明書 | 現在の証明書の取得、登録（証明書と秘密鍵）、削除 |
| ログ | 直近のサーバーログの取得（指定した番号以降） |
| 監査ログ | 監査ログの取得 |

- Ki / OPc の取得を別操作に分けるのは、GUI 側で権限に応じた出し分けをしやすくするため。
- 証明書の差し替えはクライアントID を変えずに行う。証明書を更新しても、各加入者の許可クライアントの設定をやり直す必要がない。
- 詳細は `docs/openapi/admin-api.yaml` に定義する。
- 管理API用のサーバー証明書は管理APIの対象にしない。初回起動時に自己署名を自動生成して Valkey に保存し、作り直しはコマンド（`admin-cert reset`）で行う。

### 8.3 AV用サーバー証明書

- 自己署名または持ち込みとする。
- 初回起動時に証明書がなければ自己署名を自動生成する。
- 差し替えは再起動なしで反映する。
- 削除は「自己署名を再生成してそれに戻す」動作とする。証明書のない状態は作らない。

## 9. データモデル（Valkey）

| キー | 型 | 内容 |
|---|---|---|
| `sub:{imsi}` | Hash | `ki`、`opc`、`sqn`（整数）、`amf`、`sqn_type`、`allow_plain`、`created_at`、`updated_at` |
| `sub:{imsi}:clients` | Set | 許可クライアントID |
| `subs` | Sorted Set | IMSI の索引。一覧のページングと前方一致検索に使う |
| `client:{id}` | Hash | `name`、`cert_pem`、`fp_sha256`、`not_after`、`enabled`、`network_name`、`created_at` |
| `clients` | Sorted Set | クライアントID の索引 |
| `clientfp:{fp}` | String | フィンガープリントからクライアントID への索引 |
| `seq:client` | String | クライアントID の発番カウンター |
| `cfg:av_tls` | Hash | AV 用サーバー証明書と秘密鍵 |
| `cfg:admin_tls` | Hash | 管理API 用サーバー証明書と秘密鍵 |
| `audit` | Stream | 監査ログ。件数上限つき |

- Ki / OPc は平文で保存する。将来、環境変数の鍵で AES-GCM 暗号化する処理を後付けできる構造にしておく。
- Valkey は AOF を有効にし `appendfsync always` とする。ポートは外部に公開せず、`requirepass` を設定する。

## 10. ログ

### 10.1 サーバーログ

- `log/slog` で JSON を標準出力に出す。ローテーションは Docker に任せる。
- 直近 N 件をメモリ上のリングバッファに保持し、管理APIで返す。再起動するとバッファは消える。
- Ki、OPc、CK、IK、CK'、IK' はログに出さない。
- 認証ベクター払い出しは、クライアントID とトレースID つきで記録する。
- 管理API のリクエストは、処理を終えるたびに `admin request completed`（メソッド、パス、ステータス、所要時間、管理クライアント、操作者、トレースID、送信元アドレス）として記録する。管理 GUI が数秒ごとに呼ぶ `GET /logs` だけは debug レベルにする（info だと、取得した記録自体がログに積もり続けるため）。

### 10.2 監査ログ

- 管理API経由の変更操作を記録する。対象は、加入者の登録・変更・削除、Ki / OPc の取得、AVクライアントの登録・変更・証明書の差し替え・削除、AV用サーバー証明書の登録・削除。
- 記録する項目は、日時、操作者 ID、管理クライアント、操作、対象、変更内容、トレースID。
- 加入者の登録と削除では、その時点の SQN、AMF、SQN 増加タイプを記録する。削除して再登録することで SQN / AMF を実質的に変更した操作を、後から追跡できるようにするため。
- Ki / OPc は値を記録せず、変更の有無だけを記録する。
- 標準出力に加えて Valkey の Stream に保存し、再起動後も残す。件数に上限を設け、古いものから捨てる。

## 11. 配備

- `compose.yaml` に aka-only-server と Valkey を定義する。設定は `.env` で与える。
- コンテナイメージは静的リンクのバイナリを最小のベースイメージに載せる。
- compose の healthcheck は `aka-only-server healthcheck` で、有効なリスナー（認証ベクターAPI、平文HTTP、管理API）に TCP で接続できるかを確かめる。mTLS のためクライアント証明書がないと要求を送れないので、待ち受けているかどうかの確認にとどめる（Valkey の状態などはログと管理API の `/status` で見る）。
- healthcheck は接続してすぐ切るので、サーバーは TLS のハンドシェイクの前の切断（`http: TLS handshake error from 127.0.0.1:…: EOF`）を記録する。ループバックからのこの切断だけは DEBUG にし、ログとメモリのログのバッファが healthcheck で埋まらないようにする。外からの接続は別のアドレスから届くので、WARN のまま残る（2026-10-12）。
- 停止の合図からリスナーを閉じ終えるまで最大 10 秒かかるので、compose の `stop_grace_period` を 20 秒にする（Docker の既定の猶予 10 秒では強制終了と重なる）。
- Docker が公開したポートは ufw の規則を通らないため、公開範囲は `ports` のバインド先アドレスで制御する。
- 同一ホスト上の別の compose プロジェクト（AKA-RADIUS サーバー、BFF など）とは、共有の Docker ネットワークでつなぐ。Valkey はこのネットワークに出さない。

## 12. テスト

- Milenage は TS 35.208 4.3 のテストセット（20 件）で検証する。
- AKA' の鍵導出は RFC 5448 Appendix C のテストベクター（4 件）で検証する。
- 再同期、各 SQN パターン、複数ベクター生成は単体テストで固定する。
- 同時リクエストで SQN が重複しないことを、実際の Valkey を使う結合テストで確認する。
- 管理API は、ハンドラーからストアまでを実際の Valkey に対して通しで確かめる。
- Valkey を使うテストは、接続先を環境変数（`AKA_TEST_VALKEY_ADDR`）で指定したときだけ実行する。
- GitHub Actions の CI が、push と pull request のたびにテスト（Valkey の結合テストを含む）、イメージのビルド、README の手順の通し確認を実行する。依存と標準ライブラリの既知の脆弱性は、別のワークフローが push と pull request のたびと毎週 govulncheck で調べる。
- 管理API と BFF の契約は、web-gui-for-aka-only-server の CI がこのリポジトリの main を相手に確かめる。管理API を変えたときは、そちらの CI も確かめる。

## 13. 開発フェーズ

1. AKA コア + Valkey + 認証ベクターAPI（mTLS / 平文HTTP）
2. 管理API
3. BFF / GUI（web-gui-for-aka-only-server）

フェーズ1では、加入者とクライアントをコマンド（`aka-only-server subscriber` / `client`）で投入して EAP-AKA サーバーから試せる。使い方は `README.md` を参照。

| フェーズ | 状態 |
|---|---|
| 1 | 実装済み |
| 2 | 実装済み |
| 3 | 実装済み（web-gui-for-aka-only-server） |

### 13.1 今後の課題

| 項目 | 内容 |
|---|---|
| 認証ベクターAPI のトレースID | 対応済み（2026-10-12。§5.1、認証ベクターAPI 0.2.0-draft） |

## 14. ドキュメント

| ファイル | 内容 |
|---|---|
| `docs/design-overview.md` | 本書 |
| `docs/openapi/av-api.yaml` | 認証ベクターAPI の仕様 |
| `docs/openapi/admin-api.yaml` | 管理API の仕様 |
| `docs/data-model.md` | Valkey のキー設計と Lua スクリプトの仕様 |
| `docs/operation-guide.md` | 導入、証明書の作成と登録、同一ホストのクライアントとの接続、バックアップ、更新手順 |
