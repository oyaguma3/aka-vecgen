# 運用ガイド

- 対象: aka-vecgen を VPS などで動かす人。
- 関連: [README](../README.md)（起動と基本操作）、[設計概要（PoC。今の作り）](poc/design-overview.md)、[管理API](openapi/admin-api.yaml)

## 1. 構成

`docker compose` で 2 つのコンテナを動かす。

| コンテナ | 内容 |
|---|---|
| `aka-vecgen` | 認証ベクターAPI と管理API。`docker compose ps` で healthy になれば、有効なリスナーがすべて待ち受けている |
| `valkey` | データの保存先。ホストにもほかのプロジェクトにもポートを公開しない |

| リスナー | コンテナ内のポート | ホスト側の公開先（既定） | 用途 |
|---|---|---|---|
| AV / mTLS | 8443 | `0.0.0.0:8443` | 認証ベクターAPI |
| 管理 | 9443 | `127.0.0.1:9443` | 管理API（管理クライアントを設定するまで起動しない） |

ホスト OS は Debian を主対象とする。ホストに必要なのは Docker Engine と compose プラグインだけである。

## 2. 証明書

CA は使わない。サーバー証明書は自己署名または持ち込み、クライアント証明書は登録済みのものとフィンガープリントで照合する。

| 証明書 | 使う場所 | 用意の仕方 | 相手側での扱い |
|---|---|---|---|
| AV 用サーバー証明書 | AV / mTLS リスナー | 初回起動時に自己署名を自動生成。管理API で持ち込みの証明書に差し替えられる | AVクライアントが信頼する証明書として設定する |
| AVクライアント証明書 | AVクライアント | クライアントごとに作り、管理API かコマンドで登録する | ― |
| 管理API 用サーバー証明書 | 管理リスナー | 初回起動時に自己署名を自動生成 | 管理クライアントが信頼する証明書として設定する |
| 管理クライアント証明書 | BFF など | 管理クライアントごとに作り、フィンガープリントを `.env` に書く | ― |

### 2.1 サーバー証明書の SAN

自己署名のサーバー証明書には、`.env` の `VECGEN_AV_TLS_HOSTS`（AV 用）と `VECGEN_ADMIN_TLS_HOSTS`（管理API 用）に書いたホスト名と IP アドレスが SAN として入る。クライアントが接続に使う名前や IP アドレスを、初回起動の前に指定しておく。

この設定は生成済みの証明書には反映されない。後から変えた場合は、証明書を作り直す。

| 証明書 | 作り直し方 | 反映 |
|---|---|---|
| AV 用 | 管理API の `DELETE /admin/v2/av-server-certificate` | 即時。以後の新しい接続から |
| 管理API 用 | `admin-cert reset` コマンド | サーバーの再起動後 |

```bash
docker compose exec -T aka-vecgen /aka-vecgen admin-cert reset > admin.pem
```

```bash
docker compose restart aka-vecgen
```

作り直すとフィンガープリントが変わるので、クライアント側に新しい証明書を配り直す。

### 2.2 クライアント証明書を作る

`client gen-cert` は、証明書と秘密鍵を 1 つの PEM にまとめて標準出力に出す。Valkey には接続しないので、サーバーの起動前でも使える。

```bash
docker compose run --rm --no-deps -T aka-vecgen client gen-cert -name radius > radius.pem
```

`-days` で有効日数を指定できる（既定は 825 日）。`openssl` などで作った自己署名証明書も使える。

### 2.3 クライアント証明書の更新

AVクライアントの証明書を更新するときは、管理API の `PUT /admin/v2/clients/{clientId}/certificate` で差し替える。クライアントID が変わらないので、各加入者の許可クライアントの設定はそのまま使える。差し替えた時点で、古い証明書では接続できなくなる。

管理クライアントの証明書を更新するときは、`.env` の `VECGEN_ADMIN_CLIENTS` のフィンガープリントを書き換えて、サーバーを再起動する。切り替え中は、新旧 2 つのフィンガープリントを別の識別名で並べておける。

## 3. 管理API を有効にする

1. 管理クライアントの証明書を作る（2.2）。
2. フィンガープリントを調べる。

   ```bash
   docker compose run --rm --no-deps -T aka-vecgen fingerprint < bff.pem
   ```

   `openssl x509 -noout -fingerprint -sha256` の出力（大文字、コロン区切り）もそのまま使える。
3. `.env` の `VECGEN_ADMIN_CLIENTS` に `識別名=フィンガープリント` を書く。複数ある場合はカンマで区切る。識別名は監査ログに残る。
4. 起動し直す。

   ```bash
   docker compose up -d
   ```

5. 管理API 用のサーバー証明書を取り出し、管理クライアントに設定する。

   ```bash
   docker compose exec -T aka-vecgen /aka-vecgen admin-cert > admin.pem
   ```

管理クライアントは全権を持つ。ユーザーごとの権限は、管理クライアント（BFF）の側で制御する。管理クライアントは、操作者の ID を `X-Operator-Id` ヘッダーで渡す。

BFF を別ホストで動かす場合は、`.env` の `VECGEN_ADMIN_PUBLISH` を、そのホストから届くアドレスに変える。

## 4. 同一ホストのクライアントとつなぐ

AKA-RADIUS サーバーや BFF を同じホストの別の compose プロジェクトで動かす場合は、共有の Docker ネットワーク経由でつなぐ。ホスト側に公開したポート（`127.0.0.1:8080` など）は、別のコンテナからは届かない。

aka-vecgen の compose は、共有ネットワーク（既定の名前は `aka-av`）を作って参加する。相手側の `compose.yaml` では、これを外部ネットワークとして参照する。

```yaml
services:
  radius:
    # ...
    networks:
      - default
      - aka-av

networks:
  aka-av:
    external: true
```

相手側のコンテナからは、ホスト名 `aka-vecgen` で接続する。

| 接続先 | URL |
|---|---|
| 認証ベクターAPI（mTLS） | `https://aka-vecgen:8443/nudm-ueau/v1/...` |
| 管理API | `https://aka-vecgen:9443/admin/v2/...` |

- `aka-vecgen` は、サーバー証明書の SAN の既定値に入っている。
- 共有ネットワークは aka-vecgen の compose が作るので、相手側より先に起動する。
- Valkey は共有ネットワークに参加しないので、相手側のコンテナからは届かない。

平文HTTP のリスナーは、MVP セットの段階 2-1 でなくした（認証ベクターAPI の契約は mTLS だけ）。同じホストのクライアントも mTLS でつなぐ。

## 5. 公開範囲

Docker が公開したポートは、ufw の規則を通らずに外部から届く。公開範囲は、`.env` のバインド先アドレスで制御する。

| 変数 | 既定値 | 考え方 |
|---|---|---|
| `VECGEN_AV_TLS_PUBLISH` | `0.0.0.0:8443` | 外部の AVクライアントから使う場合はこのまま。同一ホスト内だけで使うなら `127.0.0.1:8443` にする |
| `VECGEN_ADMIN_PUBLISH` | `127.0.0.1:9443` | BFF が別ホストにある場合だけ変える。VPN 側のアドレスに限定するのが望ましい |

mTLS のリスナーは、登録済みの証明書を提示しない接続を TLS ハンドシェイクで拒否する。

## 6. ログと監査ログ

| 種類 | 内容 | 保存先 | 再起動後 |
|---|---|---|---|
| サーバーログ | 払い出し、接続の拒否、エラーなど | 標準出力（Docker のログ）と、メモリ上の直近分 | Docker のログは残る。メモリ上の分は消える |
| 監査ログ | 管理API での変更操作と Ki / OPc の取得 | 標準出力と Valkey | 残る |

```bash
docker compose logs -f aka-vecgen
```

- 管理API では、`GET /admin/v2/logs` でメモリ上の直近分、`GET /admin/v2/audit-logs` で監査ログを取得できる。
- 管理API のリクエストは `admin request completed` として残る（`GET /admin/v2/logs` だけは debug レベルなので、既定の `info` では残らない）。管理クライアントが `X-Trace-ID` ヘッダーでトレースID を渡すと、その値がこのログと監査ログ（`traceId`）に残り、管理 GUI や統合API の記録と突き合わせられる。
- 認証ベクターの払い出しのログ（`av generated`、`av request rejected` など）には `trace_id` が付く。本PoCの vector-gateway が `X-Trace-ID` で渡した値なので、本PoC のログの `trace_id` で 1 回の認証を追える。
- 監査ログは `VECGEN_AUDIT_MAX` 件（既定 10000）を超えると古いものから消える。長く残したい場合は、Docker のログを外部に保存する。
- コマンド（`subscriber`、`client`）での操作は、監査ログに残らない。日常の操作は管理API で行う。
- Ki、OPc、CK、IK はログにも監査ログにも出ない。

Docker のログは既定では無制限に増える。`/etc/docker/daemon.json` などでローテーションを設定しておく。

## 7. バックアップと復元

データはすべて Valkey のボリューム（`valkey-data`）にある。加入者の Ki / OPc とサーバー証明書の秘密鍵が平文で入っているので、バックアップの保管場所に注意する。

ボリュームの実際の名前は `<プロジェクト名>_valkey-data` で、プロジェクト名は既定では compose ファイルのあるディレクトリ名になる。

```bash
docker volume ls
```

### 7.1 バックアップ

サーバーを止めてから、ボリュームの中身を固める。以下はボリューム名が `aka-vecgen_valkey-data` の場合の例である。

```bash
docker compose stop
```

```bash
docker run --rm -v aka-vecgen_valkey-data:/data:ro -v "$PWD":/backup valkey/valkey:9.1.2 tar czf /backup/valkey-data.tgz -C /data .
```

```bash
docker compose start
```

### 7.2 復元

ボリュームを空にしてから、バックアップを展開する。現在のデータは消える。

```bash
docker compose down
```

```bash
docker run --rm -v aka-vecgen_valkey-data:/data -v "$PWD":/backup valkey/valkey:9.1.2 sh -c 'rm -rf /data/* && tar xzf /backup/valkey-data.tgz -C /data'
```

```bash
docker compose up -d
```

バックアップを取った後に払い出した分の SQN は、復元すると巻き戻る。復元後に同じ SQN が再び払い出されると、端末が同期失敗を返し、再同期で回復する。

## 8. 更新

```bash
git pull
```

```bash
docker compose up -d --build
```

データはボリュームに残る。更新の前にバックアップを取っておく。

起動ログと管理API の `/status` の `version` に出るバージョンは、`VECGEN_VERSION`（既定 `dev`）で決まる。git のコミットを出す場合は、ビルドのときに指定する。

```bash
VECGEN_VERSION=$(git rev-parse --short HEAD) docker compose up -d --build
```

## 9. 障害時の確認

| 症状 | 確認すること |
|---|---|
| mTLS で接続できない（ハンドシェイクで切れる） | サーバーログの `client certificate rejected` の `reason`。`not registered` は未登録、`client disabled` は無効化、`outside validity period` は期限切れ |
| サーバー証明書の検証に失敗する | クライアントに設定した証明書が現在のものか（`av-cert` / `admin-cert` で取り出して比べる）。接続に使う名前が SAN に入っているか |
| 403 `AUTHENTICATION_REJECTED` | 応答は理由を区別しない（一般的な拒否）。サーバーログの `av request rejected` の `reason` で理由を確かめる: `not_found`（未登録）、`client_not_allowed`（許可クライアントにそのクライアントID がない）、`inactive`・`terminated`（加入者の状態）、`auts_invalid`（再同期の AUTS が合わない）、`client_disabled`（クライアントが無効・削除済み）、`client_unknown`（証明書を識別できない） |
| 400 `MANDATORY_IE_MISSING`（EAP-AKA'） | リクエストに `anId` があるか（EAP-AKA' では必須） |
| 400 `OPTIONAL_IE_INCORRECT`（EAP-AKA'） | リクエストの `anId` が、クライアントに設定した Network Name（未設定なら `WLAN`）と一致しているか |
| 端末が同期失敗を繰り返す | 加入者の SQN 増加タイプが USIM の SQN 検証方式に合っているか |
| 管理API に接続できない | `VECGEN_ADMIN_CLIENTS` が設定されているか。起動ログに `admin api is disabled` が出ていないか |
| `docker compose ps` で aka-vecgen が unhealthy | リスナーが待ち受けていない。`docker compose logs aka-vecgen` で起動のエラー（Valkey に接続できない、証明書の読み込みの失敗など）を確かめる。`docker compose exec aka-vecgen /aka-vecgen healthcheck` でどのリスナーかが分かる |
