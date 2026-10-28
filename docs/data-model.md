# データモデル（Valkey）

- 状態: ドラフト
- 対象: aka-vecgen が Valkey に持つデータと、その操作手順。
- 関連: [設計概要（MVP）](design-overview.md)、[もとの実装（aka-only-server）のデータモデル](https://github.com/oyaguma3/aka-only-server/blob/c2a093d0c336be039cd00f74631be5f1de4d4300/docs/data-model.md)、[認証ベクターAPI の契約](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)、[管理API](openapi/admin-api.yaml)

## 1. 前提

- Valkey は単一ノードで使う。クラスター構成は想定しない。
- 16進文字列は小文字で保存する。API では大文字・小文字のどちらも受け付け、保存時に小文字へそろえる。
- 日時は RFC 3339 形式の UTC で保存する。

## 2. キー一覧

| キー | 型 | 内容 |
|---|---|---|
| `sub:{imsi}` | Hash | 加入者 |
| `sub:{imsi}:clients` | Set | 加入者の許可クライアントID |
| `subs` | Sorted Set | IMSI の索引 |
| `client:{id}` | Hash | AVクライアント |
| `clients` | Sorted Set | クライアントID の索引 |
| `clientfp:{fp}` | String | 証明書フィンガープリントからクライアントID への索引 |
| `seq:client` | String | クライアントID の発番カウンター |
| `cfg:av_tls` | Hash | AV 用サーバー証明書と秘密鍵 |
| `cfg:admin_tls` | Hash | 管理API 用サーバー証明書と秘密鍵 |
| `cfg:kek` | String | KEK の識別子（初めての起動で書く） |
| `cfg:kek_check` | String | 決まった値を KEK で暗号化したもの（起動のときに復号して KEK を確かめる） |
| `cfg:kek_rotation` | String | `rotate-kek` の途中だけある（古い識別子:新しい識別子）。ある間は serve とコマンドが起動しない |
| `cfg:serve:alive` | String | serve が動いている印（TTL 30 秒、10 秒ごとに書き直す）。ある間は `rotate-kek` が断る |
| `audit` | Stream | 監査ログ |

## 3. 加入者

### 3.1 `sub:{imsi}`

`{imsi}` は 5〜15 桁の数字。

| フィールド | 形式 | 内容 |
|---|---|---|
| `cred` | バイト列 | Ki ‖ OPc（32 バイト）を KEK で暗号化したもの（AES-256-GCM。nonce 12 バイト ‖ 暗号文。AAD は `aka-vecgen/sub/<IMSI>`） |
| `cred_kek` | 16進 16 桁 | `cred` を暗号化した KEK の識別子（`rotate-kek` のやり直しに使う） |
| `sqn` | 10進整数（0 〜 2^48−1） | 最後に払い出した SQN。API では 16進 12 桁で表す |
| `amf` | 16進 4 桁 | AMF |
| `sqn_type` | `inc1` / `inc32` / `inc33` | SQN 増加タイプ |
| `state` | `active` / `inactive` / `terminated` | 状態（MVP の設計概要 §7）。払い出すのは `active` だけ。値がなければ払い出さない |
| `state_changed_at` | 日時 | 状態が最後に変わった日時（登録を含む） |
| `created_at` | 日時 | 登録日時 |
| `updated_at` | 日時 | 最終変更日時。SQN の払い出しでは更新しない |

### 3.2 `sub:{imsi}:clients`

許可クライアントID の集合。許可クライアントがなければキー自体が存在しない。

### 3.3 `subs`

全メンバーのスコアを 0 にして IMSI を登録する。辞書順で並ぶので、次の用途に使う。

- 件数: `ZCARD`
- 一覧のページング: `ZRANGE ... BYLEX LIMIT`
- IMSI の前方一致検索: `ZRANGE subs "[<prefix>" "[<prefix>\xff" BYLEX`

### 3.4 登録・削除

複数キーにまたがる操作は Lua スクリプトでまとめ、途中の状態が見えないようにする。

- 登録: `sub:{imsi}` が既にあれば失敗。なければ Hash、Set、索引を作る。状態は `active` か `inactive`（`terminated` では登録できない）。
- 削除: `state` が `active` なら断る（`ACTIVE`）。それ以外は Hash、Set、索引を消す。
- 変更: `state` が `terminated` なら断る。鍵（`cred`）は登録の後に変えない。
- 状態の変更: 移り方の規則を 1 つの Lua で確かめる。`terminated` からは、戻し（`reinstate`。`inactive` にする）だけが許される。同じ状態への変更は書き込まない。

## 4. SQN の払い出し

### 4.1 SQN の意味

`sqn` は「最後に払い出した SQN」を表す。SQN(48bit) = SEQ(43bit) || IND(5bit)。

現在値を S、生成数を n とすると、i 番目（1 始まり）のベクターの SQN と、払い出し後の `sqn` は次のとおり。加算は 2^48 を法とする。

| `sqn_type` | i 番目の SQN | 払い出し後の `sqn` |
|---|---|---|
| `inc1` | S + i | S + n |
| `inc32` | S + 32i | S + 32n |
| `inc33` | S + 33 + 32(i−1) | S + 33 + 32(n−1) |

`inc33` はバッチの1個目で IND を 1 進め、バッチ内では IND を固定する。IND が 31 から 0 に回るときは SEQ に桁上げする。

### 4.2 払い出しスクリプト

許可判定と SQN の更新を1つの Lua スクリプトで行う。同時リクエストがあっても同じ SQN を二重に払い出さない。

入力:

| 引数 | 内容 |
|---|---|
| `KEYS[1]` | `sub:{imsi}` |
| `KEYS[2]` | `sub:{imsi}:clients` |
| `KEYS[3]` | `client:{id}` |
| `ARGV[1]` | クライアントID |
| `ARGV[2]` | 生成数 n。0 なら SQN を進めずに現在の値を返す |
| `ARGV[3]` | 再同期で置き換える SQN。通常時は空文字列 |
| `ARGV[4]` | 要求された Network Name（`anId`）。空文字列なら照合しない（EAP-AKA' 以外） |
| `ARGV[5]` | Network Name の既定値（`WLAN`） |

処理:

判定の順は、認証ベクターAPI の契約 §9.2 のとおり、加入者に依らない検査（1）を先に、加入者に依る検査（2〜5）を後に行う。

1. 使う Network Name を決める。クライアントに `network_name` が設定されていればその値、なければ既定値。`ARGV[4]` が空でなく、この値と一致しなければ `NETWORK_NAME_MISMATCH` を返す（加入者の有無によらない）。
2. `sub:{imsi}` がなければ `NOT_FOUND` を返す。
3. `client:{id}` の `enabled` が `1` でなければ `CLIENT_DISABLED` を返す。削除済みのクライアントは `client:{id}` がないので、ここで拒否される。
4. クライアントID が `sub:{imsi}:clients` に含まれなければ `FORBIDDEN` を返す。
5. `state` が `terminated` なら `TERMINATED`、`active` でなければ `INACTIVE` を返す。
6. `ARGV[3]` があれば、S をその値に置き換える。
7. `sqn_type` と n から払い出し後の値を計算して `sqn` に書き込む。n が 0 で再同期でもなければ書き込まない。
8. `OK` とともに、S（加算前の値）、`cred`、`cred_kek`、`amf`、`sqn_type`、Network Name を返す。鍵は Go の側で要求ごとに復号する（KEK の識別子が違う、復号できない行は 500）。

拒否した場合（1〜5）は SQN を進めない。2〜5 の拒否は、認証ベクターAPI ではどれも同じ一般的な拒否（403）になり、理由はログにだけ残る。

各ベクターの SQN は、返された S と `sqn_type` から Go 側で 4.1 の式どおりに計算する。

Valkey の Lua は数値を倍精度浮動小数点で扱うが、48bit の整数は誤差なく表せる。

### 4.3 再同期

AUTS の検証には Ki と OPc が必要なので、再同期は2段階になる。

1. 払い出しスクリプトを n = 0 で実行し、許可判定をしたうえで Ki と OPc を得る。Ki、OPc と受信した RAND で AUTS の MAC-S を検証し、SQN_MS を取り出す。検証に失敗したら SQN は変更しない。
2. 取り出した SQN_MS を `ARGV[3]` に渡して、払い出しスクリプトをもう一度実行する。

2 でも許可判定をやり直すため、1 と 2 の間に加入者が変更されても不整合は起きない。

端末側の SQN は検証済みの値なので、サーバー側の SQN との大小は比べず、常に SQN_MS に置き換える。

## 5. AVクライアント

### 5.1 `client:{id}`

`{id}` は `seq:client` を `INCR` して発番する正の整数。削除しても再利用しない。同じ証明書の二重登録などで登録に失敗した場合も、発番済みの番号は欠番にする。

| フィールド | 形式 | 内容 |
|---|---|---|
| `name` | 文字列 | 表示名 |
| `cert_pem` | PEM | クライアント証明書 |
| `fp_sha256` | 16進 64 桁 | 証明書（DER）の SHA-256 |
| `not_after` | 日時 | 証明書の有効期限 |
| `enabled` | `0` / `1` | 無効なら接続を拒否する |
| `network_name` | 文字列 | EAP-AKA' の Network Name。空なら `WLAN` |
| `created_at` | 日時 | 登録日時 |

### 5.2 索引

- `clients`: スコアとメンバーの両方にクライアントID を入れる。一覧に使う。
- `clientfp:{fp}`: 値はクライアントID。同じ証明書の二重登録を防ぐ。

### 5.3 証明書の照合

クライアントの情報はメモリに持たず、必要なときに Valkey を引く。登録・変更・削除は、サーバーの再起動も通知もなしに次の接続から反映される。

| タイミング | 確認する内容 |
|---|---|
| TLS ハンドシェイク（セッション再開を含む） | 証明書が有効期間内であること。`clientfp:{fp}` があり、そのクライアントの `enabled` が `1` であること |
| リクエストごと | `clientfp:{fp}` からクライアントID を引く。なければ 403 を返す |
| 払い出しスクリプト | `client:{id}` の `enabled` と、加入者の許可クライアントに含まれること |

接続を張ったまま無効化・削除されたクライアントは、次のリクエストで拒否される。

### 5.4 証明書の差し替え

クライアントID を変えずに、`cert_pem`、`fp_sha256`、`not_after` を新しい証明書の値に置き換える。古い `clientfp:{fp}` を消して新しいものを作る。各加入者の `sub:{imsi}:clients` は変更しない。

### 5.5 削除

1. `client:{id}`、`clientfp:{fp}`、`clients` の該当メンバーを消す。この時点で、そのクライアントは接続できなくなる。
2. 後片付けとして、`subs` を一定件数ずつ読みながら、各加入者の `sub:{imsi}:clients` から該当 ID を `SREM` する。コマンドはパイプラインでまとめて送る。

ID を再利用しないので、2 が終わる前でも、残った ID によって別のクライアントが許可されることはない。

## 6. サーバー証明書（`cfg:av_tls`、`cfg:admin_tls`）

AV 用と管理API 用で、同じ形式の Hash を別々のキーに持つ。

| フィールド | 形式 | 内容 |
|---|---|---|
| `cert_pem` | PEM | サーバー証明書（中間証明書を含めてよい） |
| `key_enc` | バイト列 | 秘密鍵（PEM）を KEK で暗号化したもの（AAD は `aka-vecgen/cert/<av|admin>`） |
| `key_kek` | 16進 16 桁 | `key_enc` を暗号化した KEK の識別子 |
| `source` | `self-signed` / `uploaded` | 自動生成か持ち込みか |
| `updated_at` | 日時 | 更新日時 |

- 起動時にキーがなければ自己署名証明書を生成して保存する。`cfg:admin_tls` は、管理API を起動する場合にだけ作る。
- `cfg:av_tls` は、管理API で登録すると持ち込みの証明書に、「削除」すると再生成した自己署名証明書に置き換わる。動作中のリスナーにも即時に反映する。
- `cfg:admin_tls` は管理API では操作しない。作り直しはコマンド（`admin-cert reset`）で行い、サーバーの再起動で反映する。

## 7. 監査ログ（`audit`）

`XADD audit MAXLEN ~ <上限> * ...` で追記する。エントリID が記録日時を兼ねる。

| フィールド | 内容 |
|---|---|
| `operator` | 操作者 ID（管理クライアントがヘッダーで渡した値） |
| `mgmt_client` | 管理クライアントの識別名 |
| `action` | 操作の種類。値の一覧は [管理API](openapi/admin-api.yaml) の `AuditAction` を参照 |
| `target` | 対象（IMSI、クライアントID など） |
| `detail` | 変更内容の JSON |
| `trace_id` | トレースID（管理クライアントが `X-Trace-ID` で渡した値、またはサーバーが採番した値）。管理API 0.2.0 で追加。それより前のエントリにはない |

`detail` の内容:

- 加入者の登録と削除では、その時点の `sqn`、`amf`、`sqn_type` を入れる。
- 変更では、変更した項目の前後の値を入れる。
- Ki と OPc は入れない（登録の後に変える口はない）。

取得は `XREVRANGE` で新しい順に読み、エントリID でページングする。

コマンドの操作は、`operator` に `-operator` の値（既定 `cli`）、`mgmt_client` に `cli` を入れる。SIGHUP での読み直しは `operator` が `sighup`、`action` が `reload`。

同じ監査ログを、日ごとの追記だけのファイル（`VECGEN_AUDIT_DIR` の `audit-YYYYMMDD.jsonl`、日本時間で区切る）にも書く（設計概要 §13.2）。ファイルの 1 行は `time`・`operator`・`mgmtClient`・`action`・`target`・`detail`・`traceId`・`streamId`（上のエントリID）。

## 8. 永続化

| 設定 | 値 | 理由 |
|---|---|---|
| `appendonly` | `yes` | AOF で永続化する |
| `appendfsync` | `always` | 払い出した SQN を失わないようにする。負荷が低いので性能上の問題はない |
| `requirepass` | 設定する | 誤接続への最低限の保護 |
| ポートの公開 | しない | compose の内部ネットワークからのみ接続する |

異常終了で直前の SQN 更新が失われた場合、同じ SQN を再度払い出すことがある。端末側が同期失敗を返すので、再同期で回復する。
