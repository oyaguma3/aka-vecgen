# 運用ガイド

- 対象: aka-vecgen を MVP セットのデータ面の VPS で動かす人。
- 関連: [README](../README.md)（起動と基本操作、コマンドと設定の一覧）、[設計概要](design-overview.md)、[データモデル](data-model.md)、[管理API](openapi/admin-api.yaml)、[認証ベクターAPI の契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)（aka-mvpset）

## 1. 構成と置き場所

`docker compose` で 2 つのコンテナを動かす。

| コンテナ | 内容 |
|---|---|
| `aka-vecgen` | 認証ベクターAPI と管理API。UID 65532 で動く（distroless）。`docker compose ps` で healthy になれば、有効なリスナーがすべて待ち受けている |
| `valkey` | データの保存先。AOF を書き込みごとに同期する（払い出した SQN を失わないため）。ホストにもほかのプロジェクトにもポートを公開しない |

| リスナー | ポート | つなぐ相手 | 認証 |
|---|---|---|---|
| 認証ベクターAPI | 8443 | aka-radius（同じ VPS の共有の Docker ネットワーク `aka-av`） | mTLS。AV クライアントの証明書のピン |
| 管理API | 9443 | aka-provisioner（管理面。サービス用の WireGuard を通す） | mTLS。管理クライアントのピン（ファイル） |

MVP セットでは、データ面の VPS に aka-radius と並べて置く。

```
[aka-radius auth] ──mTLS（aka-av）──────> 8443 ┐
                                                ├ aka-vecgen ── Valkey（鍵は KEK で暗号化）
[aka-provisioner] ──mTLS（WireGuard）───> 9443 ┘
[運用者] ──SSH（運用用の WireGuard と踏み台）──> コマンド（AV クライアント、サーバー証明書、KEK）
```

ノードの上に置くもの（compose.yaml のあるディレクトリ）:

| ファイル | 内容 | 持ち主と権限 |
|---|---|---|
| `.env` | Valkey のパスワードと設定 | 運用者、600 |
| `secrets/kek` | KEK（32 バイトの乱数の 16 進）。Docker の secrets で渡す | UID 65532、600（ディレクトリ `secrets/` は 700） |
| `secrets/admin-clients` | 管理クライアントのピン（4 章） | UID 65532、600 |
| `audit/` | 監査ログの日ごとのファイル（8.2） | UID 65532、750 |
| ボリューム `<プロジェクト名>_valkey-data` | Valkey のデータ（AOF とスナップショット） | — |

## 2. 導入

ホストに要るのは Docker Engine と compose プラグインだけである（Debian 13 を主に想定する）。手順は README の「起動」と同じで、ここでは注意する点を書く。

1. `.env` を作り、`VALKEY_PASSWORD` を長い乱数にする（`openssl rand -hex 24` など）。
2. KEK を作る（README の「起動」）。**KEK を失うと、全加入者の鍵を登録し直すことになる。** 作ったらすぐ、Valkey のバックアップとは別の場所（オフライン）に写しを置く（9.1）。
3. 管理クライアントのピンのファイル（空でもよい）と `audit/` を作る。
4. サーバー証明書の SAN を決める。認証ベクターAPI 用は `VECGEN_AV_TLS_HOSTS`（aka-radius は `aka-vecgen` の名前でつなぐので、既定のままでよい）、管理API 用は `VECGEN_ADMIN_TLS_HOSTS`（aka-provisioner がつなぐ名前か WireGuard のアドレスを足す）。どちらも初めての起動で作る自己署名の証明書に入る。後から変えたら作り直す（6.1）。
5. 公開先を決める（7 章）。
6. `docker compose up -d` で起動する。

次のどれかに当たると起動しない（ログの `event_id`）。

| `event_id` | 原因 | 直し方 |
|---|---|---|
| `KEK_MISMATCH` | KEK のファイルが、Valkey に記録した識別子（`cfg:kek`）と合わない | 正しい KEK のファイルを置く。`mv` で置き換えたときは `docker compose up -d --force-recreate aka-vecgen`（10 章） |
| `KEK_MISSING` | Valkey に KEK の識別子がないのに、暗号化した加入者かサーバー証明書がある | 別の KEK で始めてしまうのを防ぐための停止。Valkey を戻し損ねたときに起きる。写しから戻し直す（9.3） |
| `KEK_ROTATION_IN_PROGRESS` | `rotate-kek` が途中で止まっている | 同じ 2 つのファイルで `rotate-kek` をもう一度行う（10 章） |
| `STARTUP_ERR` | KEK のファイルが読めない・形が違う、Valkey に届かない、`audit/` に書けない、ピンのファイルの形が違う、など | ログの `error` を見る |

初めての起動では、KEK の識別子を Valkey に書く。管理API の `GET /admin/v2/status` の `kekId` で、どの KEK で動いているかを確かめられる。

## 3. aka-radius とつなぐ

aka-radius の auth は、取得先の登録簿（aka-radius の `deployments/sources/sources.json`）に書いた取得先から、mTLS で認証ベクターを取る。aka-vecgen の側では、aka-radius を AV クライアントとして登録し、サーバー証明書を aka-radius に渡す。

1. aka-radius のクライアント証明書を作る（証明書と秘密鍵が 1 つの PEM に入る。有効日数は `-days`、既定 825 日）。

   ```bash
   docker compose run --rm --no-deps -T aka-vecgen client gen-cert -name aka-radius > aka-radius.pem
   ```

2. AV クライアントとして登録する。表示されたクライアントID を、加入者の許可クライアント（`allowedClientIds`）に使う。

   ```bash
   docker compose exec -T aka-vecgen /aka-vecgen client add -name aka-radius -cert - < aka-radius.pem
   ```

3. 認証ベクターAPI 用のサーバー証明書を取り出す。

   ```bash
   docker compose exec -T aka-vecgen /aka-vecgen av-cert > aka-vecgen-av.pem
   ```

4. aka-radius の `deployments/sources/` に 2 つのファイルを置き、登録簿に aka-vecgen を書く。`clientCertFile` と `clientKeyFile` は同じ PEM を指してよい。`serverCaFile` は 3 のサーバー証明書そのもの（自己署名なので、これが信頼の起点になる）。

   ```json
   {
     "id": "vecgen",
     "name": "aka-vecgen",
     "baseUrl": "https://aka-vecgen:8443/nudm-ueau/v1",
     "clientCertFile": "aka-radius.pem",
     "clientKeyFile": "aka-radius.pem",
     "serverCaFile": "aka-vecgen-av.pem"
   }
   ```

5. aka-radius を、aka-vecgen の compose が作る共有ネットワーク `aka-av` に入れて起動する（aka-radius の `deployments/docker-compose.aka-av.yml` を重ねる）。共有ネットワークは aka-vecgen の compose が作るので、aka-vecgen を先に起動する。Valkey は共有ネットワークに入らないので、aka-radius からは届かない。

EAP-AKA' では、aka-radius が送る `anId` が、AV クライアントの Network Name（未設定なら `WLAN`）と一致しないと 400 になる。aka-radius の `RADIUS_EAP_AKA_PRIME_NETWORK_NAME` を変えたときは、AV クライアントにも同じ値を設定する（`client update -id <ID> -network-name <名前>`）。

aka-radius から届いた要求のログの `trace_id` は、aka-radius が `X-Trace-ID` で送った値で、aka-radius のログの `trace_id` と同じである。1 回の認証を両方のログでたどれる。

## 4. 管理API と aka-provisioner

管理API の呼び出し側は aka-provisioner だけで、全権として扱う。誰が何をしてよいかは aka-ossbss が決める。

### 4.1 管理クライアントを登録する

管理クライアントは、ピンのファイル `secrets/admin-clients` に 1 行に 1 つ `識別名=フィンガープリント` の形で書く。

- `#` で始まる行と空行は無視する。
- 識別名は監査ログの `mgmtClient` に残る（例 `provisioner`）。
- 同じ識別名を 2 行まで書ける（証明書の入れ替え。4.2）。同じフィンガープリントを 2 回書くのは誤り。
- ファイルがあれば（空でも）管理API を起動し、ファイルがなければ起動しない（ログの `ADMIN_API_DISABLED`）。

1. aka-provisioner のクライアント証明書のフィンガープリントを調べる（aka-provisioner の側で作った証明書）。

   ```bash
   docker compose run --rm --no-deps -T aka-vecgen fingerprint < provisioner.pem
   ```

   `openssl x509 -noout -fingerprint -sha256` の出力（大文字、コロン区切り）もそのまま書ける。
2. ピンのファイルに書き、動いているサーバーに読み直させる（再起動は要らない）。

   ```bash
   echo "provisioner=<フィンガープリント>" | sudo tee -a secrets/admin-clients > /dev/null
   docker compose kill -s HUP aka-vecgen
   ```

3. 読み直せたことを確かめる。ログに `ADMIN_CLIENTS_RELOADED` が出て、`GET /admin/v2/status` の `adminClients` と `adminClientsLoadedAt` が変わる。ファイルの形が違えば `ADMIN_CLIENTS_RELOAD_ERR` を出し、前の設定のまま続ける。
4. 管理API 用のサーバー証明書を取り出し、aka-provisioner の下流の登録簿に設定する。

   ```bash
   docker compose exec -T aka-vecgen /aka-vecgen admin-cert > aka-vecgen-admin.pem
   ```

管理クライアントは、操作者を `X-Operator-Id`、トレースID を `X-Trace-ID` で渡す。トレースID は管理API のログ（`ADMIN_REQUEST`）と監査ログ（`traceId`）に残り、応答の `X-Trace-ID` でも返る。aka-ossbss → aka-provisioner → aka-vecgen の記録は、この値でたどる（8.3）。

### 4.2 管理クライアントの証明書を入れ替える

1. ピンのファイルに、同じ識別名で新しいフィンガープリントの行を足し、`SIGHUP` で読み直す（新旧の両方を受ける）。
2. aka-provisioner を新しい証明書に切り替える。
3. 古い行を消し、もう一度 `SIGHUP` で読み直す。

## 5. 加入者

加入者の登録・変更・状態の変更・削除は、ふだんは aka-ossbss の画面か一括投入から、aka-provisioner を通して管理API で行う。aka-vecgen の加入者のデータは aka-radius と独立で、テナントへの所属は aka-ossbss の台帳にある。

### 5.1 状態

| 状態 | 認証ベクター | 変更（AMF・SQN・方式・許可クライアント） | 削除 | 移れる先 |
|---|---|---|---|---|
| `active` | 払い出す | できる | できない（409 `SUBSCRIBER_ACTIVE`） | `inactive`、`terminated` |
| `inactive` | 一般的な拒否 | できる | できる | `active`、`terminated` |
| `terminated` | 一般的な拒否 | できない（409 `SUBSCRIBER_TERMINATED`） | できる | `inactive`（`POST …/reinstate`。理由が必須） |

### 5.2 SQN の方式の指針

加入者ごとに SQN の方式（`sqnType`）を選ぶ。USIM の SQN の確かめ方に合わせる。

| 方式 | 使いどころ |
|---|---|
| `inc32`（既定） | IND を固定し SEQ だけを進める。同じ USIM を別の生成源（他の HSS など）でも認証するときは、生成源ごとに別の IND を使うこの方式を選ぶ |
| `inc33` | 払い出しのたびに IND も進める。USIM の IND ごとの配列を使い切る作り（TS 33.102 Annex C） |
| `inc1` | IND を意識しない単純なカウンター。他の生成源と同じ USIM を共有しない試験用 |

- 方式が USIM に合わないと、端末が同期失敗（AUTS）を返し続ける。aka-radius は再同期を 1 回まで行うので、毎回の認証が再同期つきになるか、失敗する。
- 方式は登録の後も変えられる（`PATCH`。`terminated` を除く）。

### 5.3 鍵を誤って登録したとき

登録の後に鍵（Ki・OPc）を変える口はない（鍵の通り道を登録の 1 つに限るため）。鍵を誤ったときは、`inactive` にして削除し、登録し直す。

1. 今の SQN を控える（`GET /admin/v2/subscribers/{imsi}` の `sqn`）。
2. `PUT /admin/v2/subscribers/{imsi}/state` で `inactive` にする（`active` のままでは削除できない）。
3. `DELETE /admin/v2/subscribers/{imsi}` で削除する。
4. `POST /admin/v2/subscribers` で、正しい鍵と、1 で控えた SQN（`sqn`）・AMF・方式・許可クライアント・状態を指定して登録し直す。SQN を控えた値にしておくと、端末の SQN より小さくならず、再同期なしで認証できる（小さくなっても再同期で戻る）。

aka-ossbss から行うときは、その手順に従う（台帳と下流の 2 つを合わせて扱う）。ノードの上で直接行うと、台帳との突き合わせで差として見つかる。

### 5.4 ノードの上のコマンドで登録する

`subscriber add` は、試験と初めの確かめのためのコマンドである。本物の鍵は、コマンドの引数に書かない（シェルの履歴とホストのプロセスの一覧に残る）。`-ki` と `-opc` を省くと、標準入力の 1 行（`<Ki> <OPc>`）から読む。

```bash
docker compose exec -T aka-vecgen /aka-vecgen subscriber add -imsi 440100123456789 -clients 1 < keys.txt
```

`keys.txt` は使い終えたら消す。コマンドでの操作も監査ログに残る（操作者は `-operator`、既定 `cli`）。

### 5.5 鍵の読み出し

鍵を読み出す口（`GET /admin/v2/subscribers/{imsi}/keys`）は、既定で無効（404 `KEY_EXPORT_DISABLED`）。別の生成源への移し替えのような、まれな作業のときだけ有効にする。

1. `.env` の `VECGEN_KEY_EXPORT=true` にし、`docker compose up -d aka-vecgen` で作り直す（起動のログに `KEY_EXPORT_ENABLED` が出る）。
2. 作業を終えたら `false` に戻し、もう一度作り直す。

読み出すたびに監査ログに残る（`subscriber.keys.read`。値は残さない）。

## 6. 証明書

CA は使わない。サーバー証明書は自己署名（または持ち込み）で、クライアント証明書は登録したものとフィンガープリントで照合する。

| 証明書 | 使う場所 | 有効期間 | 入れ替え |
|---|---|---|---|
| 認証ベクターAPI 用のサーバー証明書 | 8443 | 自己署名は 10 年 | `av-cert reset`（作り直し）か `av-cert replace`（持ち込み）の後に `SIGHUP`（6.1） |
| AV クライアントの証明書（aka-radius） | aka-radius | `client gen-cert` は既定 825 日 | `client replace-cert`（6.2） |
| 管理API 用のサーバー証明書 | 9443 | 自己署名は 10 年 | `admin-cert reset` の後に `SIGHUP`（6.1） |
| 管理クライアントの証明書（aka-provisioner） | aka-provisioner | aka-provisioner の側で決める | ピンのファイル（4.2） |

期限は `GET /admin/v2/status`（`avServerCertificateNotAfter`、`adminServerCertificateNotAfter`）と `GET /admin/v2/clients`（AV クライアント）で見られる。

### 6.1 サーバー証明書を作り直す

SAN を変えたとき、秘密鍵が漏れたおそれがあるときに作り直す。

```bash
docker compose exec -T aka-vecgen /aka-vecgen av-cert reset > aka-vecgen-av.pem
docker compose kill -s HUP aka-vecgen
```

- `SIGHUP` で、動いているサーバーが新しい証明書を読み直す（ログの `SERVER_CERT_RELOADED`）。以後の新しい接続から効く。
- 作り直すとフィンガープリントが変わるので、相手に配り直す。認証ベクターAPI 用は、aka-radius の登録簿の `serverCaFile` を差し替え、aka-radius の auth に `SIGHUP` を送る。**aka-radius の側を差し替えるまでの間、aka-radius は aka-vecgen につなげない**（認証が失敗する）。新しい証明書を aka-radius に置く準備をしてから、2 つの `SIGHUP` を続けて送る。
- 管理API 用は `admin-cert reset` で同じように作り直し、aka-provisioner の登録簿を差し替える。
- 持ち込みの証明書に替えるときは `av-cert replace -cert <PEM> -key <PEM>`。ファイルはコンテナの中のパスで指すので、`docker compose run --rm --no-deps -v ./av.pem:/tmp/av.pem:ro -v ./av-key.pem:/tmp/av-key.pem:ro aka-vecgen av-cert replace -cert /tmp/av.pem -key /tmp/av-key.pem` のようにマウントする（UID 65532 で読めるようにする）。その後に `SIGHUP`。

### 6.2 AV クライアントの証明書を入れ替える

```bash
docker compose run --rm --no-deps -T aka-vecgen client gen-cert -name aka-radius > aka-radius-new.pem
docker compose exec -T aka-vecgen /aka-vecgen client replace-cert -id <ID> < aka-radius-new.pem
```

- クライアントID は変わらないので、加入者の許可クライアントはそのまま使える。
- 差し替えた時点で、古い証明書では接続できなくなる（接続と要求のたびに Valkey を見るため。`SIGHUP` は要らない）。aka-radius の登録簿の証明書をすぐ差し替え、aka-radius の auth に `SIGHUP` を送る。

AV クライアントの有効と無効（`client update -enable` / `-disable`）と削除（`client del`）も、すぐに効く。クライアントID は使い回さない。

## 7. 公開範囲

Docker が公開したポートは、ufw の規則を通らずに外から届く。公開範囲は `.env` のバインド先のアドレスで決める。

| 変数 | 既定 | 考え方 |
|---|---|---|
| `VECGEN_AV_TLS_PUBLISH` | `127.0.0.1:8443` | aka-radius は共有ネットワークでつなぐので、ホストに出すのは手元での確かめのためだけ。別ホストの AV クライアントから使うときだけ、そのホストから届くアドレスに変える |
| `VECGEN_ADMIN_PUBLISH` | `127.0.0.1:9443` | MVP セットでは、サービス用の WireGuard のアドレス（例 `10.x.x.x:9443`）にする。`0.0.0.0` にはしない |

- WireGuard のアドレスに結び付けたうえで、nftables の `DOCKER-USER` で aka-provisioner のアドレスからだけ通す。規則の中身は、MVP セットの配置（段階 5）の文書で決める。
- mTLS のリスナーは、登録した証明書を出さない接続を TLS のハンドシェイクで断る（ログの `AV_CLIENT_REJECTED`、`ADMIN_CLIENT_REJECTED`）。

## 8. ログと監査ログ

| 種類 | 内容 | 置き場所 | 持つ期間 |
|---|---|---|---|
| ログ | 払い出し、拒否、管理API の要求、起動と読み直し、誤り | 標準出力（Docker のログ） | ノードで 2 週間（8.1） |
| 監査ログ | 管理API とコマンドの操作、鍵の読み出し、KEK の入れ替え、`SIGHUP` での読み直し | Valkey の Stream と `audit/` の日ごとのファイル | Stream は `VECGEN_AUDIT_MAX` 件、ファイルはノードで `VECGEN_AUDIT_RETENTION_DAYS` 日（既定 14） |

Ki・OPc・CK・IK・CK'・IK'・XRES・KEK は、ログにも監査ログにも出さない。

> **IMSI はマスクしない。** 運用上、調査・解析のトレーサビリティを優先するため、aka-vecgen のログは IMSI をマスクせずに出す（aka-radius もマスクの既定をオフにしている）。生の IMSI がログに出ることを認識しておくこと。ログを取りに行く監視用の PC にも生の IMSI が残るので、その PC の保管とアクセスできる人も、ノードと同じく限る。

### 8.1 ログ

JSON（1 行に 1 つ）で標準出力に出す。どの行にも `event_id` があり、要求に関わる行には `trace_id` がある。

```bash
docker compose logs -f aka-vecgen
```

| `event_id` | 内容 |
|---|---|
| `AV_ISSUED` | 払い出した（IMSI、クライアントID、認証タイプ、再同期の有無） |
| `AV_REJECTED` | 要求を断った。`reason` が理由（8.4） |
| `AV_FAILED` | 中の誤りで 500 か 503 にした（`reason` に `subscriber_cred_invalid` など） |
| `AV_CLIENT_REJECTED` | 認証ベクターAPI の TLS のハンドシェイクで証明書を断った（`not registered`、`client disabled`、`outside validity period`） |
| `ADMIN_REQUEST` / `ADMIN_ERROR` | 管理API の要求（`trace_id`、操作者、状態の符号、時間） / 管理API の中の誤り |
| `ADMIN_CLIENT_REJECTED` | 管理API の TLS のハンドシェイクで証明書を断った（`not configured`、`outside validity period`） |
| `ADMIN_CLIENTS_LOADED` / `ADMIN_CLIENTS_RELOADED` / `ADMIN_CLIENTS_RELOAD_ERR` | ピンのファイルを読んだ / 読み直した / 読み直せず前のまま続ける |
| `SERVER_CERT_LOADED` / `SERVER_CERT_GENERATED` / `SERVER_CERT_RELOADED` / `SERVER_CERT_RELOAD_ERR` | サーバー証明書を読んだ / 作った / 読み直した / 読み直せず前のまま続ける |
| `AUDIT` / `AUDIT_WRITE_ERR` / `AUDIT_MAINTAIN_ERR` | 監査ログを書いた / 書けなかった（操作は成功のまま） / ファイルの圧縮か削除に失敗した |
| `KEY_EXPORT_ENABLED` | 鍵の読み出しの口を有効にして起動した |
| `STARTING` / `LISTENING` / `SHUTDOWN` | 起動・待ち受け・停止 |
| `KEK_MISMATCH` など | 起動の失敗（2 章の表） |

Docker のログは、既定では際限なく増える。ノードで 2 週間持てるように、`/etc/docker/daemon.json` でローテーションを設定する（例 `"log-driver": "json-file"`、`"log-opts": {"max-size": "50m", "max-file": "10"}`）。

データ面の VPS では、aka-radius と同じ Fluent Bit に送り、アプリごとのファイルに書いて日ごとに圧縮する（aka-radius の設計概要の決定事項 10）。そのための重ね合わせのファイルと、Fluent Bit の出力先は、aka-radius の段階 2-5 で足す。

### 8.2 監査ログ

管理API とコマンドの操作を、Valkey の Stream（`GET /admin/v2/audit-logs` で見る）と、日ごとのファイル `audit/audit-YYYYMMDD.jsonl` に書く。

- ファイルは日本時間で日を区切る。前の日までのファイルは gzip で圧縮し（最後に書いてから 10 分たってから）、`VECGEN_AUDIT_RETENTION_DAYS` を過ぎたものは消す。どちらも serve が起動のときと 1 時間ごとに行う。
- 1 行の項目は `time`・`operator`・`mgmtClient`・`action`・`target`・`detail`・`traceId`・`streamId`（Stream のエントリID）。
- 主な `action`: `subscriber.create`・`update`・`state`・`reinstate`・`delete`・`keys.read`、`client.create`・`update`・`certificate.replace`・`delete`、`av-server-certificate.replace`・`reset`、`admin-server-certificate.reset`、`kek.rotate`、`reload`（`SIGHUP`。操作者は `sighup`）。
- Stream は件数の上限で古いものから押し出される。長く残すのはファイルのほうで、監視用の PC が押し出される前に取りに行く。
- ファイルに書けなかったときは、操作は成功のまま返し、ログに `AUDIT_WRITE_ERR` を出す。このログは監視で拾う（`audit/` の空きと権限を確かめる）。

監視用の PC は、運用用の WireGuard と踏み台を通して、rsync over SSH で取りに行く（PC の受信の口は開けない）。取りに行く対象は、圧縮した前の日までのファイル（`audit-*.jsonl.gz`）と、Docker のログ（または 8.1 の Fluent Bit のファイル）。

### 8.3 トレースID で記録をたどる

aka-ossbss の操作から aka-vecgen の記録までは、同じトレースID でたどれる。

1. aka-ossbss の監査ログか画面で、操作のトレースID を調べる。
2. aka-provisioner の監査ログで、同じトレースID の `vecgen.*` の行を探す。
3. aka-vecgen で同じトレースID を探す。ログは `trace_id`、監査ログのファイルは `traceId`。

   ```bash
   docker compose logs aka-vecgen | grep '"trace_id":"<トレースID>"'
   ```

   ```bash
   grep -h '"traceId":"<トレースID>"' audit/audit-*.jsonl; zgrep -h '"traceId":"<トレースID>"' audit/audit-*.jsonl.gz
   ```

一括投入の行ごとの操作は、トレースID にジョブの ID が入る。認証は、aka-radius のログの `trace_id` でたどる（3 章）。

### 8.4 認証ベクターの拒否の理由

応答は理由を区別しない（固定の本文の 403 `AUTHENTICATION_REJECTED`）。理由はログの `AV_REJECTED` の `reason` にだけ残す。

| `reason` | 意味 | 確かめること |
|---|---|---|
| `not_found` | 加入者が登録されていない | 台帳と aka-vecgen の登録。aka-radius の加入者の取得先 |
| `client_not_allowed` | 加入者の許可クライアントに、そのクライアントID がない | 加入者の `allowedClientIds` |
| `inactive` / `terminated` | 加入者の状態 | 状態（5.1） |
| `auts_invalid` | 再同期の AUTS が合わない | 鍵の誤り（5.3）か、端末の側の不具合 |
| `client_disabled` | AV クライアントが無効 | `client show -id <ID>` |
| `client_unknown` | ハンドシェイクの後にクライアントが削除された | AV クライアントの一覧 |

EAP-AKA' の 400: `MANDATORY_IE_MISSING` は `anId` がない、`OPTIONAL_IE_INCORRECT` は `anId` が Network Name と合わない（3 章）。

## 9. KEK とバックアップ

### 9.1 KEK

- KEK は `secrets/kek` にだけある。Valkey には識別子しか持たない。
- 作ったとき・入れ替えたときに、写しをオフライン（VPS とも Valkey のバックアップとも別の場所）に置く。
- **KEK を失うと、全加入者の鍵を登録し直すことになる**（Valkey のバックアップがあっても戻せない）。サーバー証明書も作り直しになる。
- 入れ替えた後も、古い KEK は、入れ替える前に取った Valkey のバックアップを捨てるまで保管しておく。
- KEK と Valkey のバックアップは、同じ場所に置かない（両方を手にした人は全加入者の鍵を読める）。

### 9.2 Valkey のバックアップ

データはすべて Valkey にある。加入者の鍵とサーバー証明書の秘密鍵は KEK で暗号化してある。

毎日、止めずにスナップショットを取って写す（`scripts/backup-valkey.sh`。`BGSAVE` で取り、書き終えたのを確かめてから `docker compose cp` で写す）。認証は止まらない。

```bash
mkdir -p backups && chmod 700 backups
scripts/backup-valkey.sh backups/valkey-$(date +%Y%m%d).rdb
```

- 写しはノードの外（監視用の PC など）へ移し、ノードには長く置かない。
- 写しを取ったときの KEK の識別子（`GET /admin/v2/status` の `kekId`）を、写しと一緒に記録しておく。
- 更新の前など、止めた状態で取りたいときは、`docker compose stop aka-vecgen` の後に同じスクリプトを使う（止めている間は認証が失敗する）。

### 9.3 戻し方

戻すと、今のデータは消える。

1. 写しを取ったときの KEK が `secrets/kek` にあることを確かめる。
2. 写しから戻す（`scripts/restore-valkey.sh`。止めてから、一時の Valkey で写しを読み込み、AOF を作り直す）。

   ```bash
   scripts/restore-valkey.sh backups/valkey-20261028.rdb
   ```

3. 起動する。KEK が違えば `KEK_MISMATCH` で起動しない。`secrets/kek` を別のファイルに置き換えたときは、`docker compose up -d --force-recreate aka-vecgen` で作り直す（10 章と同じ理由）。

   ```bash
   docker compose up -d
   ```

写しの後の変更はなくなる。

- 写しの後に登録・削除・状態の変更をした加入者は、台帳との突き合わせ（aka-ossbss）で差として見つかる。
- 写しの後に払い出した分の SQN は巻き戻る。巻き戻った SQN で払い出すと、端末が同期失敗を返し、aka-radius の再同期で回復する（その加入者の次の 1 回の認証が再同期つきになる）。

Valkey は AOF が有効だと、AOF がないときにスナップショットを読まずに空のデータで始まる。ボリュームに写しを置いて起動するだけでは戻らないので、必ずスクリプトで戻す。

## 10. KEK の入れ替え

KEK が漏れたおそれがあるとき、または運用の決まりで定期に入れ替える。入れ替えの間、認証ベクターAPI と管理API は止まる。

1. 入れ替える前に Valkey のバックアップを取る（9.2）。
2. 新しい KEK を作る。

   ```bash
   openssl rand -hex 32 > secrets/kek-new
   sudo chown 65532 secrets/kek-new && sudo chmod 600 secrets/kek-new
   ```

3. aka-vecgen を止めて、入れ替える（動いていると `rotate-kek` は断る）。

   ```bash
   docker compose stop aka-vecgen
   docker compose run --rm --no-deps -v ./secrets/kek-new:/run/secrets/kek-new:ro aka-vecgen rotate-kek -old /run/secrets/kek -new /run/secrets/kek-new
   ```

   加入者を 500 件ずつ暗号化し直す。途中で止まったら、同じ 2 つのファイルでもう一度行えば続きから終わる。終わるまでは、`serve` もほかのコマンドも起動しない（`KEK_ROTATION_IN_PROGRESS`）。
4. `secrets/kek` を新しいファイルに置き換え、コンテナを作り直して起動する。

   ```bash
   mv secrets/kek secrets/kek-old && mv secrets/kek-new secrets/kek
   docker compose up -d --force-recreate aka-vecgen
   ```

   `docker compose start aka-vecgen` では起動しない。KEK のファイルは 1 つのファイルとしてコンテナに渡していて、コンテナは作ったときのファイルを指し続けるので、`mv` で置き換えても古い KEK を読み、`KEK_MISMATCH` で止まる。
5. `GET /admin/v2/status` の `kekId` が新しい識別子になったことを確かめ、新しい KEK の写しをオフラインに置く（9.1）。`secrets/kek-old` はオフラインに移してノードから消す。

入れ替えは監査ログに残る（`kek.rotate`）。

## 11. 更新

MVP セットの VPS の上ではイメージをビルドしない（並べてビルドすると数 GB を使う）。イメージは手元でビルドして VPS に送る（送り方は MVP セットの配置の文書で決める）。

1. 更新の前に、Valkey のバックアップを取る（9.2）。
2. イメージを入れ替え、`docker compose up -d` で作り直す。データはボリュームに残る。

起動のログと `GET /admin/v2/status` の `version` に出る版は、ビルドのときの `VECGEN_VERSION`（既定 `dev`）で決まる。

```bash
VECGEN_VERSION=$(git rev-parse --short HEAD) docker compose build
```

`/status` の `avApiContractVersion` は、合わせている認証ベクターAPI の契約の版（今は 1.0.0）。

## 12. 障害時の確かめ

| 症状 | 確かめること |
|---|---|
| aka-vecgen が起動しない | 起動のログの `event_id`（2 章の表） |
| `docker compose ps` で unhealthy | リスナーが待ち受けていない。`docker compose exec aka-vecgen /aka-vecgen healthcheck` でどのリスナーかが分かる |
| aka-radius から mTLS でつなげない | aka-vecgen のログの `AV_CLIENT_REJECTED` の `reason`（`not registered` は未登録か証明書の取り違え、`client disabled` は無効、`outside validity period` は期限切れ）。ログがなければ、aka-radius が `aka-av` に入っているか、`serverCaFile` が今の `av-cert` と同じか、`baseUrl` のホスト名が SAN に入っているか |
| 403 `AUTHENTICATION_REJECTED` | ログの `AV_REJECTED` の `reason`（8.4） |
| 500 `SYSTEM_FAILURE` | ログの `AV_FAILED` の `reason`。`subscriber_cred_invalid` は、鍵の暗号文が今の KEK で復号できない（段階 2-1 までの平文の行か、壊れた行）。登録し直す（5.3） |
| 503 `NF_CONGESTION` | Valkey に届かない。`docker compose ps valkey`、`docker compose logs valkey`、ディスクの空き（AOF は書き込みごとに同期する） |
| 端末が同期失敗を繰り返す | 加入者の SQN の方式が USIM に合っているか（5.2）。戻した後なら、1 回は再同期になる（9.3） |
| 管理API につなげない | `secrets/admin-clients` があるか（起動のログに `ADMIN_API_DISABLED` が出ていないか）、`ADMIN_CLIENT_REJECTED` の `reason`、`VECGEN_ADMIN_PUBLISH` と nftables |
| ピンを書き換えたのに効かない | `SIGHUP` を送ったか。`ADMIN_CLIENTS_RELOAD_ERR` が出ていないか |
| 監査ログのファイルが増えない | `AUDIT_WRITE_ERR`（`audit/` の権限と空き） |
| `rotate-kek` が断る | serve が動いている（強制終了したときは、動いている印が消えるまで最大 30 秒待つ）、または違う組の KEK でやり直そうとしている |
