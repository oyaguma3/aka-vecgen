# aka-vecgen

[![CI](https://github.com/oyaguma3/aka-vecgen/actions/workflows/ci.yml/badge.svg)](https://github.com/oyaguma3/aka-vecgen/actions/workflows/ci.yml)
[![govulncheck](https://github.com/oyaguma3/aka-vecgen/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/oyaguma3/aka-vecgen/actions/workflows/govulncheck.yml)

> このリポジトリは、VPS に分けて置いて顧客を収容する **MVP セット**（[aka-mvpset](https://github.com/oyaguma3/aka-mvpset)）の、認証ベクターを作るノードです。PoC セット（[eapaka-pocset](https://github.com/oyaguma3/eapaka-pocset) の `pocset-v1.0.1`）の [aka-only-server](https://github.com/oyaguma3/aka-only-server) の履歴を引き継いで作りました（もとのコミット `c2a093d`）。
>
> MVP セットの段階 2-1 まで済んでいます（加入者の状態、認証ベクターAPI の[契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)への合わせ込み、平文HTTP の廃止、管理API 2.0.0（`/admin/v2`）の加入者の口）。鍵の暗号化（2-2）と管理API の残り（2-3）はこれからです。設計は[設計概要](docs/design-overview.md)、段階 1 までの作りは [PoC の設計概要](docs/poc/design-overview.md)にあります。コマンドは `aka-vecgen`、環境変数の接頭辞は `VECGEN_` です。

指定した IMSI に対して、Milenage による AKA 認証ベクターを払い出す API サーバーです。EAP-AKA / EAP-AKA' の RADIUS サーバーなどから使うことを想定しています。

- 認証ベクターAPI は 3GPP TS 29.503 Nudm_UEAU の GenerateAv をベースにしています。
- クライアントは mTLS で識別し、加入者ごとに払い出しを許可するクライアントを指定します。
- データは Valkey に保存します。
- 加入者やクライアントは、管理API またはコマンドで操作します。
- GUI は持ちません。管理 GUI は [web-gui-for-aka-only-server](https://github.com/oyaguma3/web-gui-for-aka-only-server) で提供しています。

個人利用・検証用途のサーバーです。Ki / OPc は Valkey に平文で保存します。

## 現在の状態

| フェーズ | 内容 | 状態 |
|---|---|---|
| 1 | AKA コア、Valkey、認証ベクターAPI（mTLS。平文HTTP は MVP の段階 2-1 でなくした） | 実装済み |
| 2 | 管理API | 実装済み |
| 3 | BFF / Web GUI（web-gui-for-aka-only-server） | 実装済み |

## 起動

Docker Engine と compose プラグインが必要です。

```bash
cp .env.example .env
```

`.env` の `VALKEY_PASSWORD` を変更してから起動します。

```bash
docker compose up -d --build
```

初回起動時に、認証ベクターAPI 用の自己署名サーバー証明書を自動生成します。クライアントが `localhost` 以外の名前や IP アドレスで接続する場合は、初回起動の前に `.env` の `VECGEN_AV_TLS_HOSTS` に指定してください。

## クライアントと加入者の登録

ここではコマンドで登録します。管理API でも同じ操作ができます。以下のコマンドは、起動中のコンテナの中で実行します。

クライアント証明書と秘密鍵を生成します（手元の `openssl` で作った自己署名証明書でも構いません）。

```bash
docker compose exec -T aka-vecgen /aka-vecgen client gen-cert -name radius > radius.pem
```

証明書を登録します。発番されたクライアントID が表示されます。

```bash
docker compose exec -T aka-vecgen /aka-vecgen client add -name radius -cert - < radius.pem
```

加入者を登録し、払い出しを許可するクライアントID を指定します。

```bash
docker compose exec -T aka-vecgen /aka-vecgen subscriber add -imsi 440100123456789 -ki 465b5ce8b199b49faa5f0a2ee238a6bc -opc cd63cb71954a9f4e48a5994e37a02baf -clients 1
```

クライアント側でサーバーを検証するために、サーバー証明書を取り出します。

```bash
docker compose exec -T aka-vecgen /aka-vecgen av-cert > server.pem
```

## 認証ベクターの取得

```bash
curl --cacert server.pem --cert radius.pem -X POST https://localhost:8443/nudm-ueau/v1/imsi-440100123456789/hss-security-information/eap-aka/generate-av -d '{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1}'
```

```json
{"hssAuthenticationVectors":[{"avType":"EAP_AKA","rand":"...","xres":"...","autn":"...","ck":"...","ik":"..."}]}
```

| パス | ボディの `hssAuthType` | 返す鍵 |
|---|---|---|
| `eap-aka` | `EAP_AKA` | CK、IK |
| `umts-aka` | `UMTS_AKA` | CK、IK |
| `eap-aka-prime` | `EAP_AKA_PRIME` | CK'、IK'（ボディの `anId` に、クライアントに許したネットワーク名を入れる。既定は `WLAN`） |

`numOfRequestedVectors` は 1〜5 です。再同期は `resynchronizationInfo`（`rand` と `auts`）を付けて要求します。EAP-AKA' では `anId`（ネットワーク名）が必須です。仕様の正本は aka-mvpset の[認証ベクターAPI の契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)（[OpenAPI](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/openapi/av-api.yaml)）で、加入者が登録されていない・許可されていない・inactive・terminated・AUTS の誤りは、どれも同じ 403 の本文で返します（理由はログの `reason` に残ります）。

## 管理API

加入者、AVクライアント、AV 用サーバー証明書、ログ、監査ログを操作する API です。管理クライアントを設定するまでは起動しません。

管理クライアント（BFF など）の証明書を用意し、フィンガープリントを調べます。

```bash
docker compose run --rm --no-deps -T aka-vecgen client gen-cert -name bff > bff.pem
```

```bash
docker compose run --rm --no-deps -T aka-vecgen fingerprint < bff.pem
```

`.env` の `VECGEN_ADMIN_CLIENTS` に `識別名=フィンガープリント` の形で設定し、起動し直します。

```bash
docker compose up -d
```

管理API 用のサーバー証明書を取り出して、接続を確認します。

```bash
docker compose exec -T aka-vecgen /aka-vecgen admin-cert > admin.pem
```

```bash
curl --cacert admin.pem --cert bff.pem https://localhost:9443/admin/v2/status
```

操作の一覧は [docs/openapi/admin-api.yaml](docs/openapi/admin-api.yaml)、設定と運用の詳細は [docs/operation-guide.md](docs/operation-guide.md) を参照してください。

## コマンド

| コマンド | 内容 |
|---|---|
| `serve` | サーバーを起動する（既定） |
| `subscriber add` / `show` / `del` | 加入者を登録・表示・削除する |
| `client add` / `list` / `del` | AVクライアントを登録・一覧・削除する |
| `client gen-cert` | クライアント用の自己署名証明書と秘密鍵を生成する |
| `av-cert` | 認証ベクターAPI 用のサーバー証明書を表示する |
| `admin-cert` | 管理API 用のサーバー証明書を表示する。`admin-cert reset` で作り直す |
| `fingerprint` | 標準入力の証明書（PEM）の SHA-256 フィンガープリントを表示する |
| `healthcheck` | 動いているサーバーのリスナーに接続できるかを確かめる（compose の healthcheck が使う） |

各コマンドのオプションは `-h` で確認できます。`subscriber add` の `-sqn-type` には SQN 増加タイプ（`inc1` / `inc32` / `inc33`）を指定します。

## 設定

`.env` で指定します。

| 変数 | 既定値 | 内容 |
|---|---|---|
| `VALKEY_PASSWORD` | （必須） | Valkey のパスワード |
| `VECGEN_AV_TLS_PUBLISH` | `0.0.0.0:8443` | mTLS リスナーを公開するホスト側のアドレスとポート |
| `VECGEN_AV_TLS_HOSTS` | `localhost,127.0.0.1,aka-vecgen` | AV 用の自己署名サーバー証明書の SAN。生成済みの証明書には反映されない |
| `VECGEN_ADMIN_CLIENTS` | （空） | 管理クライアント。`識別名=フィンガープリント` のカンマ区切り。空なら管理API を起動しない |
| `VECGEN_ADMIN_PUBLISH` | `127.0.0.1:9443` | 管理API を公開するホスト側のアドレスとポート |
| `VECGEN_ADMIN_TLS_HOSTS` | `localhost,127.0.0.1,aka-vecgen` | 管理API 用の自己署名サーバー証明書の SAN。生成済みの証明書には反映されない |
| `VECGEN_SHARED_NETWORK` | `aka-av` | 同一ホスト上の別の compose プロジェクトと共有する Docker ネットワークの名前 |
| `VECGEN_LOG_LEVEL` | `info` | ログレベル |
| `VECGEN_LOG_BUFFER` | `1000` | 管理API で返すためにメモリに保持するログの件数 |
| `VECGEN_AUDIT_MAX` | `10000` | 監査ログの保持件数の上限 |
| `VECGEN_VERSION` | `dev` | 起動ログと管理API の `/status` に出すバージョン（ビルドのときに埋め込む） |

Docker が公開したポートは ufw の規則を通りません。公開範囲は `VECGEN_AV_TLS_PUBLISH`、`VECGEN_ADMIN_PUBLISH` のアドレスで制御してください。

## 開発

Go 1.27.3 を使います。

```bash
go test ./...
```

Valkey を使う結合テストは、接続先を指定したときだけ実行します。テストは論理データベース 1 番と 2 番の全データを消すので、専用の Valkey を使ってください。

```bash
docker run -d --rm --name aka-test-valkey -p 127.0.0.1:16379:6379 valkey/valkey:9.1.2
```

```bash
VECGEN_TEST_VALKEY_ADDR=127.0.0.1:16379 go test ./...
```

GitHub Actions（`.github/workflows/ci.yml`）で、push と pull request のたびに次を実行します。

| ジョブ | 内容 |
|---|---|
| テスト | gofmt の確認、`go vet`、race 検出つきのテスト（Valkey の結合テストを含む） |
| イメージと compose の設定 | Docker イメージのビルドと compose の設定の検査 |
| README の手順の通し確認 | この README の「起動」から「認証ベクターの取得」までを実行し、3 つの認証タイプでベクターを取得する。未登録のクライアントが接続できないことも確かめる |

依存と標準ライブラリの既知の脆弱性は、`.github/workflows/govulncheck.yml` が push と pull request のたびと、毎週月曜に govulncheck で調べます。

管理API と BFF の契約は、[web-gui-for-aka-only-server](https://github.com/oyaguma3/web-gui-for-aka-only-server) の CI がこのリポジトリの main を相手に確かめます。

## ドキュメント

- [設計概要（MVP）](docs/design-overview.md)
- [PoC の設計概要（今の作り）](docs/poc/design-overview.md)
- [認証ベクターAPI の契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)（aka-mvpset。OpenAPI も同じリポジトリ）
- [管理API](docs/openapi/admin-api.yaml)
- [データモデル](docs/data-model.md)
- [運用ガイド](docs/operation-guide.md)
