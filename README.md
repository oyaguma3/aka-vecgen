# aka-vecgen

[![CI](https://github.com/oyaguma3/aka-vecgen/actions/workflows/ci.yml/badge.svg)](https://github.com/oyaguma3/aka-vecgen/actions/workflows/ci.yml)
[![govulncheck](https://github.com/oyaguma3/aka-vecgen/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/oyaguma3/aka-vecgen/actions/workflows/govulncheck.yml)

> このリポジトリは、VPS に分けて置いて顧客を収容する **MVP セット**（[aka-mvpset](https://github.com/oyaguma3/aka-mvpset)）の、認証ベクターを作るノードです。PoC セット（[eapaka-pocset](https://github.com/oyaguma3/eapaka-pocset) の `pocset-v1.0.1`）の [aka-only-server](https://github.com/oyaguma3/aka-only-server) の履歴を引き継いで作りました（もとのコミット `c2a093d`）。
>
> MVP セットの段階 2（データ面）の改修を終えています。設計は[設計概要](docs/design-overview.md)、導入と運用は[運用ガイド](docs/operation-guide.md)にあります。

指定した IMSI に対して、Milenage による AKA 認証ベクターを払い出す API サーバーです。MVP セットでは、データ面の VPS で aka-radius と並べて置き、aka-radius から使います。

- 認証ベクターAPI は、aka-mvpset の[認証ベクターAPI の契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)（1.0.0。3GPP TS 29.503 Nudm_UEAU の GenerateAv がもと）を実装しています。
- クライアントは mTLS で識別し（証明書のピン留め）、加入者ごとに払い出しを許可するクライアントを指定します。
- 加入者は状態（`active` / `inactive` / `terminated`）を持ちます。
- 加入者の鍵（Ki・OPc）とサーバー証明書の秘密鍵は、KEK（鍵を暗号化する鍵）で暗号化して Valkey に保存します。
- 加入者の操作は管理API 2.0.0（`/admin/v2`。呼び出し側は aka-provisioner）で、AV クライアント・サーバー証明書・KEK の操作はノードの上のコマンドで行います。
- 操作は監査ログ（Valkey の Stream と日ごとのファイル）に残します。
- GUI は持ちません（MVP セットの画面は aka-ossbss）。

## 起動

Docker Engine と compose プラグインが必要です。

```bash
cp .env.example .env
```

`.env` の `VALKEY_PASSWORD` を変更します。

KEK は 32 バイトの乱数を 16 進で書いたファイルで、Valkey とは別に `secrets/kek` に置きます。コンテナは UID 65532 で動くので、この UID で読めるようにします。

```bash
mkdir -p secrets && chmod 700 secrets
openssl rand -hex 32 > secrets/kek
sudo chown 65532 secrets/kek && sudo chmod 600 secrets/kek
```

（イメージを作った後なら `docker compose run --rm --no-deps -T aka-vecgen gen-kek > secrets/kek` でも作れます。イメージがまだないと、ビルドの経過が同じ出力に混じるので、先に `docker compose build` をします。）**KEK を失うと、全加入者の鍵を登録し直すことになります。** 作ったら、Valkey のバックアップとは別の場所（オフライン）にも写しを置いてください（[運用ガイド](docs/operation-guide.md) 9 章）。

管理クライアントのピンのファイル（下の「管理API」。空でもよい）と、監査ログの日ごとのファイルの置き場所（`audit/`）を作ります。どちらも UID 65532 で読み書きできるようにします。

```bash
touch secrets/admin-clients
sudo chown 65532 secrets/admin-clients && sudo chmod 600 secrets/admin-clients
mkdir -p audit && sudo chown 65532 audit && sudo chmod 750 audit
```

起動します（`audit/` に書けなければ起動しません）。

```bash
docker compose up -d --build
```

初めての起動で、KEK の識別子（SHA-256 の先頭 8 バイトの 16 進）を Valkey に書きます。以降の起動では、KEK のファイルがその識別子と合わなければ起動しません。

初めての起動で、認証ベクターAPI 用と管理API 用の自己署名のサーバー証明書を作ります。クライアントが `localhost`・`127.0.0.1`・`aka-vecgen` 以外の名前で接続する場合は、初めての起動の前に `.env` の `VECGEN_AV_TLS_HOSTS`・`VECGEN_ADMIN_TLS_HOSTS` に書きます。

## クライアントと加入者の登録

以下のコマンドは、起動中のコンテナの中で実行します。

クライアント証明書と秘密鍵を生成します（手元の `openssl` で作った自己署名証明書でも構いません）。

```bash
docker compose exec -T aka-vecgen /aka-vecgen client gen-cert -name radius > radius.pem
```

証明書を登録します。発番されたクライアントID が表示されます。

```bash
docker compose exec -T aka-vecgen /aka-vecgen client add -name radius -cert - < radius.pem
```

加入者を登録し、払い出しを許可するクライアントID を指定します（ここでは試験の値の鍵を引数で渡しています。本物の鍵は引数に書かず、標準入力で渡します。[運用ガイド](docs/operation-guide.md) 5.4）。

```bash
docker compose exec -T aka-vecgen /aka-vecgen subscriber add -imsi 440100123456789 -ki 465b5ce8b199b49faa5f0a2ee238a6bc -opc cd63cb71954a9f4e48a5994e37a02baf -clients 1
```

クライアント側でサーバーを検証するために、サーバー証明書を取り出します。

```bash
docker compose exec -T aka-vecgen /aka-vecgen av-cert > server.pem
```

aka-radius とつなぐ手順（共有ネットワーク `aka-av` と、aka-radius の取得先の登録簿）は、[運用ガイド](docs/operation-guide.md) 3 章にあります。

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

`numOfRequestedVectors` は 1〜5 です。再同期は `resynchronizationInfo`（`rand` と `auts`）を付けて要求します。EAP-AKA' では `anId`（ネットワーク名）が必須です。加入者が登録されていない・許可されていない・inactive・terminated・AUTS の誤りは、どれも同じ 403 の本文で返します（理由はログの `reason` に残ります。[運用ガイド](docs/operation-guide.md) 8.4）。

## 管理API

加入者の登録・変更・状態の変更・削除・一覧・一括取得と、AV クライアント・AV 用サーバー証明書・監査ログの読み出しを行う API（2.0.0、`/admin/v2`）です。呼び出し側は aka-provisioner です。鍵の読み出しの口は、既定で無効です（`VECGEN_KEY_EXPORT=true` のときだけ）。

管理クライアントは、ピンのファイル `secrets/admin-clients` に、1 行に 1 つ `識別名=フィンガープリント` の形で書きます。ファイルがあれば（空でも）管理API を起動し、書いた管理クライアントだけを通します。

管理クライアントの証明書を用意し、フィンガープリントを調べます。

```bash
docker compose run --rm --no-deps -T aka-vecgen client gen-cert -name prov > prov.pem
```

```bash
docker compose run --rm --no-deps -T aka-vecgen fingerprint < prov.pem
```

ピンのファイルに書き、動いているサーバーに読み直させます（再起動は要りません）。

```bash
echo "prov=<フィンガープリント>" | sudo tee -a secrets/admin-clients > /dev/null
docker compose kill -s HUP aka-vecgen
```

管理API 用のサーバー証明書を取り出して、接続を確認します。

```bash
docker compose exec -T aka-vecgen /aka-vecgen admin-cert > admin.pem
```

```bash
curl --cacert admin.pem --cert prov.pem https://localhost:9443/admin/v2/status
```

操作の一覧は [docs/openapi/admin-api.yaml](docs/openapi/admin-api.yaml) にあります。

## コマンド

| コマンド | 内容 |
|---|---|
| `serve` | サーバーを起動する（既定） |
| `gen-kek` | KEK を作る。`-out` を省くと標準出力に書く。ファイルは権限 600 で作り、上書きしない |
| `rotate-kek -old <ファイル> -new <ファイル>` | 加入者の鍵とサーバー証明書の秘密鍵を新しい KEK で暗号化し直す（[運用ガイド](docs/operation-guide.md) 10 章） |
| `subscriber add` / `show` / `del` | 加入者を登録・表示・削除する。`add` は `-ki`・`-opc` を省くと標準入力の 1 行（`<Ki> <OPc>`）から読む |
| `client add` / `list` / `show` / `del` | AV クライアントを登録・一覧・表示・削除する |
| `client update -id <ID>` | AV クライアントの表示名（`-name`）、有効と無効（`-enable` / `-disable`）、Network Name（`-network-name`）を変える |
| `client replace-cert -id <ID>` | AV クライアントの証明書を差し替える（`-cert`、既定は標準入力） |
| `client gen-cert` | クライアント用の自己署名証明書と秘密鍵を生成する |
| `av-cert` | 認証ベクターAPI 用のサーバー証明書を表示する。`av-cert replace -cert <PEM> -key <PEM>` で持ち込みの証明書に差し替え、`av-cert reset` で自己署名を作り直す |
| `admin-cert` | 管理API 用のサーバー証明書を表示する。`admin-cert reset` で作り直す |
| `fingerprint` | 標準入力の証明書（PEM）の SHA-256 フィンガープリントを表示する |
| `healthcheck` | 動いているサーバーのリスナーに接続できるかを確かめる（compose の healthcheck が使う） |

各コマンドのオプションは `-h` で確認できます。`subscriber add` の `-sqn-type` には SQN の方式（`inc1` / `inc32` / `inc33`）を指定します（選び方は[運用ガイド](docs/operation-guide.md) 5.2）。

- 登録・変更・削除のコマンドは、監査ログに残します。操作者は `-operator` で名前を付けられます（既定 `cli`）。
- AV クライアントの変更は、すぐに効きます（接続と要求ごとに Valkey を見るため）。
- サーバー証明書の差し替えと作り直し、ピンのファイルの変更は、`docker compose kill -s HUP aka-vecgen` で動いているサーバーに反映します。

Valkey のバックアップと戻しは `scripts/backup-valkey.sh`・`scripts/restore-valkey.sh` で行います（[運用ガイド](docs/operation-guide.md) 9 章）。

## 設定

`.env` で指定します。

| 変数 | 既定値 | 内容 |
|---|---|---|
| `VALKEY_PASSWORD` | （必須） | Valkey のパスワード |
| `VECGEN_AV_TLS_PUBLISH` | `127.0.0.1:8443` | 認証ベクターAPI を公開するホスト側のアドレスとポート。aka-radius は共有ネットワークでつなぐので、ホストへの公開は手元での確かめのため |
| `VECGEN_AV_TLS_HOSTS` | `localhost,127.0.0.1,aka-vecgen` | AV 用の自己署名サーバー証明書の SAN。生成済みの証明書には反映されない |
| `VECGEN_ADMIN_PUBLISH` | `127.0.0.1:9443` | 管理API を公開するホスト側のアドレスとポート（MVP セットではサービス用の WireGuard のアドレス） |
| `VECGEN_ADMIN_TLS_HOSTS` | `localhost,127.0.0.1,aka-vecgen` | 管理API 用の自己署名サーバー証明書の SAN。生成済みの証明書には反映されない |
| `VECGEN_KEY_EXPORT` | `false` | 鍵の読み出しの口を有効にする（別の生成源への移し替えのときだけ） |
| `VECGEN_SHARED_NETWORK` | `aka-av` | 同一ホスト上の別の compose プロジェクト（aka-radius）と共有する Docker ネットワークの名前 |
| `VECGEN_LOG_LEVEL` | `info` | ログレベル |
| `VECGEN_AUDIT_MAX` | `100000` | 監査ログの Stream の保持件数の上限 |
| `VECGEN_AUDIT_RETENTION_DAYS` | `14` | 監査ログのファイルをノードで持つ日数 |
| `VECGEN_VERSION` | `dev` | 起動ログと管理API の `/status` に出すバージョン（ビルドのときに埋め込む） |

compose がコンテナに渡す変数（compose を使わずに動かす場合）:

| 変数 | 既定値 | 内容 |
|---|---|---|
| `VECGEN_VALKEY_ADDR` / `VECGEN_VALKEY_PASSWORD` | — | Valkey |
| `VECGEN_KEK_FILE` | `/run/secrets/kek` | KEK のファイル |
| `VECGEN_AV_TLS_ADDR` / `VECGEN_ADMIN_ADDR` | — | 待ち受けるアドレス（compose では `:8443` / `:9443`） |
| `VECGEN_ADMIN_CLIENTS_FILE` | `/run/secrets/admin-clients` | 管理クライアントのピンのファイル。ファイルがなければ管理API を起動しない。`SIGHUP` で読み直す |
| `VECGEN_AUDIT_DIR` | `/data/audit` | 監査ログの日ごとのファイルの置き場所 |

Docker が公開したポートは ufw の規則を通りません。公開範囲は `VECGEN_AV_TLS_PUBLISH`、`VECGEN_ADMIN_PUBLISH` のアドレスで制御してください（[運用ガイド](docs/operation-guide.md) 7 章）。

## 開発

Go 1.27.3 を使います。

```bash
go test ./...
```

Valkey を使う結合テストは、接続先を指定したときだけ実行します。テストは論理データベース 0〜2 番の全データを消すので、専用の Valkey を使ってください。

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
| README の手順の通し確認 | この README の「起動」から「認証ベクターの取得」までを実行し、3 つの認証タイプでベクターを取得する。AV 用サーバー証明書を作り直して `SIGHUP` で反映できること、操作が監査ログのファイルに残ること、未登録のクライアントが接続できないこと、Valkey のバックアップと戻しも確かめる |
| 認証ベクターAPI の適合試験 | aka-mvpset の `conformance/av-api/`（固定のコミット）を走らせる |

依存と標準ライブラリの既知の脆弱性は、`.github/workflows/govulncheck.yml` が push と pull request のたびと、毎週月曜に govulncheck で調べます。

管理API と aka-provisioner の契約の試験は、aka-provisioner を作り直す MVP の段階 3-1 で、aka-provisioner の CI がこのリポジトリの固定のコミットを相手に確かめます。

## ドキュメント

- [設計概要](docs/design-overview.md)
- [運用ガイド](docs/operation-guide.md)
- [認証ベクターAPI の契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)（aka-mvpset。OpenAPI も同じリポジトリ）
- [管理API](docs/openapi/admin-api.yaml)
- [データモデル](docs/data-model.md)
