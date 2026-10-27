# aka-vecgen 設計概要（下書き）

- 作成日: 2026-10-25
- 状態: 下書き。§17 の確認事項は 2026-10-25 にすべて推奨案で合意した（§3.2 の決定事項 1〜11）。
- 置き場所: 2026-10-27（MVP セットの段階 1）に、aka-mvpset の `docs/nodes/aka-vecgen.md` から本リポジトリの `docs/design-overview.md` に移した。
- 対象: 認証ベクターを作るノード aka-vecgen（もとは aka-only-server。以下「もとの実装」）。
- 関連:
  - aka-mvpset の[要件と構成の概要](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/requirements-overview.md)（以下「概要」）: §5（配置）、§6.1・§6.3・§6.4（加入者のデータ・状態・台帳）、§10（一括投入）、§11（権限）、§12（鍵と秘密の値）、§13（ログ）、§15（バックアップ）、§17.1（改修）
  - 認証ベクターAPI の契約（以下「契約」）: [av-api-contract.md](https://github.com/oyaguma3/aka-mvpset/blob/main/docs/av-api-contract.md)。とくに §16.1（aka-vecgen の改修 V1〜V7）
  - もとの実装: aka-only-server。今の作りは本リポジトリの [`docs/poc/design-overview.md`](poc/design-overview.md)、[`docs/data-model.md`](data-model.md)、`docs/openapi/admin-api.yaml`（管理API 0.2.0）
  - 手本にする実装: radsec-ca（KEK と鍵の暗号化 §6、管理クライアントのピン §9.1）、eapaka-node-provisioner（管理クライアントの認証、操作者・トレースID）

## 1. 位置づけ

指定した IMSI の認証ベクターを Milenage で作って返すノード。データ面に aka-radius と並べて置く。

```
[aka-radius] ──mTLS（ノードの中の Docker のネットワーク）──> 認証ベクターAPI（8443）
                                                             ─────── aka-vecgen ─────── Valkey（Ki・OPc は暗号化）
[aka-provisioner] ──mTLS（サービス用の WireGuard）──────────> 管理API（9443）             KEK（ファイル）
[運用者] ──SSH（運用用の WireGuard と踏み台）──> コマンド（AV クライアント、サーバー証明書、KEK）
```

- aka-vecgen は、IMSI ごとに鍵（Ki・OPc）・AMF・SQN・許可クライアント・状態を持つ（概要の決定事項 4）。テナントへの所属は持たない（aka-ossbss の台帳にある。決定事項 6）。
- 認証ベクターAPI は契約（1.0.0）を実装する。aka-radius から見て、aka-vecgen は「同じ契約を実装した取得先」の 1 つにすぎない。
- 管理API の呼び出し側は aka-provisioner だけで、全権として扱う。誰が何をしてよいか（役割）は aka-ossbss が決める（概要 §6.4、§11）。
- 加入者のデータは aka-radius と独立に管理する（決定事項 6）。

## 2. 範囲

| 区分 | 内容 |
|---|---|
| 対象 | Milenage による認証ベクターの生成（EAP-AKA、EAP-AKA'、UMTS-AKA）、SQN の管理と再同期、加入者の登録・変更・状態・削除、鍵の保存時の暗号化と KEK の入れ替え、AV クライアント（証明書のピン留め）、一括取得と一覧、監査ログとその書き出し |
| 対象外 | 画面（web-gui-for-aka-only-server は MVP セットに含めない。概要 §17.2）、平文HTTP の認証ベクターAPI（§17 の B5）、OP の扱い（常に OPc）、Milenage 以外の方式、テナント・認可・セッション、一括投入のジョブ（aka-ossbss が 1 件ずつの API を呼ぶ。概要 §10.2）、冗長化 |

## 3. 決定事項

### 3.1 概要と契約で決めたこと

| # | 内容 | 出どころ |
|---|---|---|
| 1 | IMSI ごとに鍵・許可クライアント・状態を持つ。同じ契約を実装した他のノードに差し替えられる | 概要の決定事項 4 |
| 2 | 状態は Active / Inactive / Terminated。Terminated から Inactive に戻すのは専用の API で、理由を必須にする。Active は物理削除できない | 決定事項 7〜9、概要 §6.3 |
| 3 | 鍵を書き込めるのは一括投入と、システム管理者の個別の登録だけ。鍵を画面に出さない。読み出しの API は既定で無効にする | 決定事項 16、概要 §12.2 |
| 4 | Ki・OPc は AES-256-GCM で暗号化し、AAD に IMSI を入れる。KEK はファイル（Docker の secrets）で渡し、DB には KEK の識別子だけを持つ。radsec-ca の作りにそろえる | 概要 §12.1 |
| 5 | 下流の管理クライアントは aka-provisioner だけ。一括取得（IMSI を 500 件まで。鍵を返さない）と一覧の索引を持つ | 概要 §6.4 |
| 6 | 管理クライアントのピンを、再起動せずに読み直せるようにする | 概要 §12.3 |
| 7 | MVP で変える API は新しい大きい版にし、PoC セットとの互換は持たせない（管理API は `/admin/v2`） | 段階 0 の進め方 S5 |
| 8 | 認証ベクターAPI は契約に合わせる（一般的な拒否、ネットワーク名の照合を加入者を調べる前に、EAP-AKA' の `anId` を必須に） | 契約の決定事項 2・10、§16.1 |
| 9 | ログの IMSI のマスクは既定でオフ（もとの実装もマスクしていない） | 決定事項 26 |

### 3.2 本書で決めたこと

| # | 内容 | 決定日 |
|---|---|---|
| 1 | module パスは `github.com/oyaguma3/aka-vecgen`、コマンド名は `aka-vecgen`、環境変数の接頭辞は `VECGEN_`（§4。確認事項 B1） | 2026-10-25 |
| 2 | 状態の値は小文字の `active` / `inactive` / `terminated`。変更は `PUT /admin/v2/subscribers/{imsi}/state`、Terminated からの戻しは `POST /admin/v2/subscribers/{imsi}/reinstate`（理由が必須）。登録では状態（`active` か `inactive`）を必須にする。aka-radius も同じ値と口にそろえる（§7、§10.2。B2） | 2026-10-25 |
| 3 | Ki ‖ OPc を 1 つの暗号文（AAD は IMSI を含む文字列）にする。起動の確認は `cfg:kek_check` の復号で行う。`rotate-kek` は止めて行い、行ごとの KEK の識別子（`cred_kek`）でやり直せるようにする（§8。B3） | 2026-10-25 |
| 4 | 登録の後に鍵を変える API は作らない。誤りは `inactive` → 削除 → 登録し直しで直す。鍵の読み出しは `VECGEN_KEY_EXPORT=true` のときだけ有効にする（§8.4。B4） | 2026-10-25 |
| 5 | 平文HTTP のリスナーと加入者の `allowPlain` をなくす（§5、§6.1。B5。契約の決定事項 5） | 2026-10-25 |
| 6 | AV クライアントと AV 用のサーバー証明書の書き込みはノードの上のコマンドで行い、管理API は読み出しだけにする（§9.3。B6） | 2026-10-25 |
| 7 | 管理クライアントのピンはファイル（Docker の secrets）にして `SIGHUP` で読み直す。同じ識別名に新旧 2 つのフィンガープリントを書ける。aka-radius・aka-provisioner・radsec-ca も同じ作りにそろえる（§10.1。B7） | 2026-10-25 |
| 8 | メモリーの中のログの口（`GET /logs`）をなくす（§10.2。B8） | 2026-10-25 |
| 9 | 監査ログは Valkey の Stream に加えて、日ごとの追記だけの JSONL のファイルに書き、監視用の PC が取りに行く（§13.2。B9） | 2026-10-25 |
| 10 | 認証ベクターAPI は、Valkey に届かないときに 503 `NF_CONGESTION`、他の中の誤りで 500 `SYSTEM_FAILURE` を返す（§9.1。B10） | 2026-10-25 |
| 11 | aka-vecgen は `Idempotency-Key` を扱わない。登録の 409 と削除の 404 で「既にある」「ない」を返し、再送の判定は aka-provisioner に任せる（§10.1。B11） | 2026-10-25 |

## 4. 技術方針

- もとの実装の方針を引き継ぐ。言語は Go 1.27.3。標準ライブラリを優先する（`net/http`、`crypto/tls`、`crypto/aes`・`crypto/cipher`、`encoding/json/v2`、`log/slog`）。
- 外部依存は `github.com/wmnsk/milenage` と `github.com/valkey-io/valkey-go` だけ（もとの実装と同じ）。
- module パスは `github.com/oyaguma3/aka-vecgen`、コマンド名は `aka-vecgen`、環境変数の接頭辞は `VECGEN_`（§17 の B1）。
- データベースは Valkey（単一ノード、AOF、`appendfsync always`）。
- 配備は Docker Compose。コンテナは distroless の nonroot。KEK は Docker の secrets で渡す。
- ブランチは `main` に直接コミットする（もとの実装と同じ。prefix なしの日本語の件名）。

## 5. 待ち受け

| 口 | ポート | 待ち受けるアドレス | 認証 |
|---|---|---|---|
| 認証ベクターAPI | 8443（HTTPS） | データ面のノードの中の Docker のネットワーク（aka-radius と共有する external のネットワーク）。ホストに公開しない | mTLS。AV クライアントの証明書のピン（§9） |
| 管理API | 9443（HTTPS） | サービス用の WireGuard のアドレス（管理面の aka-provisioner から） | mTLS。管理クライアントのピン（§10.1） |

- もとの実装の平文HTTP のリスナー（8080）はなくす（§17 の B5）。
- TLS は 1.2 以上。サーバー証明書は、AV 用と管理用を分ける（もとの実装と同じ。§9.3）。
- Valkey はどこにも公開しない（compose の内部のネットワークだけ）。

## 6. 加入者のデータ

### 6.1 `sub:{imsi}`（Hash）

| フィールド | 形式 | 内容 | もとの実装からの変更 |
|---|---|---|---|
| `cred` | バイト列（nonce ‖ 暗号文） | Ki ‖ OPc（32 バイト）を AES-256-GCM で暗号化したもの（§8） | `ki`・`opc` の平文をやめる |
| `cred_kek` | 16 進 16 桁 | `cred` を暗号化した KEK の識別子（`rotate-kek` のやり直しに使う。§8.3） | 新しく足す |
| `sqn` | 10 進整数（0〜2^48−1） | 最後に払い出した SQN | — |
| `amf` | 16 進 4 桁 | AMF（既定 `8000`。EAP-AKA' では separation bit が 1 である必要がある） | — |
| `sqn_type` | `inc1` / `inc32` / `inc33` | SQN の方式（既定 `inc32`。§6.4） | — |
| `state` | `active` / `inactive` / `terminated` | 状態（§7） | 新しく足す |
| `state_changed_at` | 日時 | 状態が最後に変わった日時（登録を含む） | 新しく足す |
| `created_at`、`updated_at` | 日時 | 登録・最終変更の日時（SQN の払い出しでは変えない） | — |

- `allow_plain` はなくす（平文HTTP をなくすため）。
- 許可クライアント（`sub:{imsi}:clients`、Set）と IMSI の索引（`subs`、Sorted Set）は、もとの実装のまま。

### 6.2 一覧と一括取得

- 一覧は `subs` を辞書順にたどる（カーソルつき、1 ページ 500 件まで。IMSI の前方一致で絞れる）。台帳との突き合わせ（概要 §6.4）は、これで全件をたどる（20 万件で 400 ページ）。
- 一括取得は、IMSI を 500 件まで受け取り、あるものの中身（鍵を除く）と、ない IMSI の一覧を返す（パイプラインでまとめて読む）。

### 6.3 大きさの見込み

- 加入者 1 件あたり、Hash（約 9 フィールド）・Set・索引で 0.5 KB 前後。20 万件で約 100 MB（規模の試験で測る）。
- SQN の払い出しは認証 1 回に 1 回の書き込みで、ピーク 50 TPS でも AOF の `always` で足りる（もとの実装と同じ判断）。

### 6.4 SQN の方式の指針

運用ガイドに次の指針を書く（概要 §6.1）。

| 方式 | 使いどころ |
|---|---|
| `inc32`（既定） | IND を固定し SEQ だけを進める。同じ USIM を別の生成源（他の HSS など）でも認証するときは、生成源ごとに別の IND を使うこの方式を選ぶ |
| `inc33` | 払い出しのたびに IND も進める。USIM の IND ごとの配列を使い切る作り（TS 33.102 Annex C） |
| `inc1` | IND を意識しない単純なカウンター。他の生成源と同じ USIM を共有しない試験用 |

## 7. 状態

### 7.1 規則（概要 §6.3）

| 状態 | 認証ベクター | 変更（AMF・SQN・方式・許可クライアント） | 物理削除 | 移れる先 |
|---|---|---|---|---|
| `active` | 払い出す | できる | できない（409 `SUBSCRIBER_ACTIVE`） | `inactive`、`terminated` |
| `inactive` | 一般的な拒否 | できる | できる | `active`、`terminated` |
| `terminated` | 一般的な拒否 | できない（409 `SUBSCRIBER_TERMINATED`） | できる | `inactive`（専用の API。理由が必須） |

- 登録のときの状態は `active` か `inactive` を必ず指定する（`terminated` では登録できない）。
- 状態の移り方は API が強制する（概要 §6.3）。同じ状態への変更は何もせず 200 を返し、監査ログには残す。
- 払い出しの Lua で `state` を確かめ、`active` でなければ一般的な拒否（理由 `inactive` / `terminated`）にする。

### 7.2 Terminated から戻す

- `POST /admin/v2/subscribers/{imsi}/reinstate`（本文: `reason`、1〜500 文字）。`terminated` から `inactive` にする。他の状態では 409 `STATE_TRANSITION_NOT_ALLOWED`。
- 使えるのがシステム管理者だけであることは aka-ossbss が守る（aka-vecgen は管理クライアントを全権として扱う）。理由と操作者は監査ログに残す。

## 8. 鍵の保管

### 8.1 暗号化（概要 §12.1、radsec-ca §6 にそろえる）

- Ki ‖ OPc（32 バイト）を AES-256-GCM で暗号化して `cred` に入れる。nonce は 12 バイトの乱数。AAD は `aka-vecgen/sub/<IMSI>`（暗号文を別の加入者の行に移しても復号できないようにする）。
- KEK は 32 バイトの乱数で、ファイル（`VECGEN_KEK_FILE`。Docker の secrets）で渡す。Valkey には KEK の識別子（SHA-256 の先頭 8 バイトの 16 進）を `cfg:kek` に持つ。
- 払い出しの Lua は `cred` をそのまま返し、Go の側で復号して Milenage に渡す。平文の鍵はメモリーに持ち続けない（要求ごとに復号して捨てる）。
- 一括投入の待ちのファイルの暗号化（概要 §12.1）は aka-ossbss の役目で、aka-vecgen には関係しない。

### 8.2 起動のときの確認

- KEK のファイルを読めない、32 バイトでない、識別子が `cfg:kek` と合わない場合は起動しない。
- 初めての起動（`cfg:kek` がない）では識別子を書き込む。
- 加入者を全件復号して確かめることはしない（20 万件を毎回読むのは重い）。代わりに `cfg:kek_check`（決まった値を KEK で暗号化したもの）を復号できることを確かめる。

### 8.3 KEK の入れ替えとバックアップ

- `aka-vecgen rotate-kek -old <ファイル> -new <ファイル>`: 止めてから、全加入者の `cred` を 500 件ずつ読み、新しい KEK で暗号化し直して書く。途中で止まっても続きからやり直せるように、各行に KEK の識別子を持たせる（`cred_kek`）。
- `aka-vecgen gen-kek -out <ファイル>`: KEK を作る。
- バックアップは Valkey の AOF と定期のスナップショット（概要 §15）。暗号文なので、KEK と一緒に置かない。**KEK を失うと全加入者の鍵を入れ直すことになる**（運用ガイドに書く）。

### 8.4 鍵の書き込みと読み出し

- 鍵を書き込めるのは登録（`POST /admin/v2/subscribers`）だけ。登録の後に鍵を変える API は作らない（§17 の B4）。鍵を誤って登録したときは、`inactive` にして削除し、登録し直す（SQN と AMF は登録のときに指定できる）。
- 鍵の読み出し（`GET /admin/v2/subscribers/{imsi}/keys`）は `VECGEN_KEY_EXPORT=true` のときだけ有効にする（既定は無効で 404）。別の生成源への移し替えのような、まれな作業のためだけに残す。使うたびに監査ログに残す（値は残さない）。
- 鍵はログ・監査ログ・応答（読み出しの API を除く）に出さない。

## 9. 認証ベクターAPI

### 9.1 契約への合わせ方

契約 §16.1 の V1〜V7 を行う。

| # | 内容 |
|---|---|
| V1 | 未登録・許可なし・`inactive`・`terminated`・AUTS の誤り・無効のクライアントを、固定の本文の 403 にする。理由はログに残す（`not_found`、`client_not_allowed`、`inactive`、`terminated`、`auts_invalid`、`client_disabled`） |
| V2 | 判定の順: TLS でのクライアントの識別 → 形の検査 → ネットワーク名の照合（クライアントの `network_name` だけで行う）→ 払い出しの Lua（有無・許可・状態）→ 再同期なら AUTS |
| V3 | `EAP_AKA_PRIME` で `anId` がなければ 400 `MANDATORY_IE_MISSING` |
| V4 | クライアントの `network_name` を「許す値」として扱う（空なら `WLAN`） |
| V5 | `Cache-Control: no-store` を付ける。Valkey に届かないときは 503 `NF_CONGESTION`、他の中の誤りは 500 `SYSTEM_FAILURE`（§17 の B10） |
| V6 | 平文HTTP のリスナーをなくす（§17 の B5） |
| V7 | 適合試験（契約 §14）を CI で走らせる |

- Milenage、AKA' の鍵の導出、SQN の方式、払い出しの Lua の原子性、再同期の 2 段の手順は、もとの実装のまま（もとの実装の設計概要 §5・§6、データモデル §4）。

### 9.2 払い出しの Lua の変更

もとの実装のデータモデル §4.2 の手順を、次のように変える。

1. `sub:{imsi}` がなければ `NOT_FOUND`。
2. クライアントが無効なら `CLIENT_DISABLED`、許可クライアントに含まれなければ `FORBIDDEN`。
3. `state` が `active` でなければ `INACTIVE` / `TERMINATED`。
4. 再同期の SQN があれば置き換え、n 個分 SQN を進める。
5. `OK` とともに、加算前の SQN、`cred`、`amf`、`sqn_type` を返す。

- ネットワーク名の照合は Lua から外し、Go の側で加入者を調べる前に行う（V2）。
- 1〜3 はどれも SQN を進めず、Go の側で同じ一般的な拒否にする。

### 9.3 AV クライアントとサーバー証明書

- AV クライアントの作り（証明書のピン留め、ID を使い回さない、ハンドシェイクと要求ごとに Valkey で確かめる、削除の後の掃除）は、もとの実装のまま（もとの実装の設計概要 §7）。
- MVP の AV クライアントは aka-radius の 1 つ（と、試験のときの適合試験のクライアント）。
- AV クライアントと AV 用のサーバー証明書の登録・変更・削除は、ノードの上のコマンド（`aka-vecgen client ...`、`aka-vecgen av-cert ...`）で行い、管理API からは一覧の読み出しだけにする（§17 の B6）。aka-ossbss は、加入者の許可クライアントを選ぶために一覧を読む。
- AV 用のサーバー証明書は、もとの実装と同じく初めての起動で自己署名を作る。aka-radius の取得先の登録簿には、この証明書を「サーバーの CA」として登録する。SAN は `VECGEN_AV_TLS_HOSTS`（例 `aka-vecgen`）。

## 10. 管理API（9443、mTLS）

項目の詳細は OpenAPI（`docs/openapi/admin-api.yaml`、2.0.0）で、段階 2 の実装のときに書く。本書では口の一覧と方針だけを書く。

### 10.1 認証・ヘッダー・エラー

- mTLS 必須。管理クライアントは、ファイル（`VECGEN_ADMIN_CLIENTS_FILE`。1 行に `識別名=フィンガープリント`）で設定する。`SIGHUP` で読み直す（再起動しない。概要 §12.3）。同じ識別名に 2 つのフィンガープリントを並べて書けるようにし、証明書の入れ替えの間は新旧の両方を受ける（§17 の B7）。読み直しは、ファイルが読めない・形が違うときは前の設定のまま続け、ログに出す。
- 管理API のサーバー証明書は、もとの実装と同じく自己署名（`aka-vecgen admin-cert reset` で作り直す）。
- `X-Operator-Id`（操作者）と `X-Trace-ID`（受け取るか採番し、応答で返す）は、もとの実装の管理API 0.2.0 と同じ。
- エラーは ProblemDetails（`application/problem+json`）で、`cause` に理由の符号を入れる。主な `cause`: `VALIDATION_ERROR`、`SUBSCRIBER_NOT_FOUND`、`SUBSCRIBER_EXISTS`、`SUBSCRIBER_ACTIVE`、`SUBSCRIBER_TERMINATED`、`STATE_TRANSITION_NOT_ALLOWED`、`UNKNOWN_CLIENT`、`KEY_EXPORT_DISABLED`、`SYSTEM_FAILURE`。
- `Idempotency-Key` は aka-vecgen では扱わない。再送の判定は aka-provisioner が行う（provisioner の設計概要 §9.2）。登録は「既にあれば 409 `SUBSCRIBER_EXISTS`」、削除は「なければ 404」なので、一括投入の「既にある」「ない IMSI は飛ばす」（概要 §10.3）はこの応答で数えられる。

### 10.2 口

すべて `/admin/v2` の下。

| 口 | 内容 | もとの実装からの変更 |
|---|---|---|
| `GET /status` | 版、契約の版、起動日時、KEK の識別子、加入者の数、AV クライアントの数、AV 用・管理用のサーバー証明書の期限、管理クライアントの識別名と読み直しの日時 | KEK・契約の版・管理クライアントを足す |
| `GET /subscribers` | 一覧（カーソル、1 ページ 500 件まで、IMSI の前方一致）。`total` を返す | 状態を含める |
| `POST /subscribers/batch-get` | 一括取得（本文: `imsis` 500 件まで）。応答: `items`（あるもの）と `notFound` | 新しく足す |
| `POST /subscribers` | 登録（本文: `imsi`、`ki`、`opc`、`state`（`active` / `inactive`）、`amf`、`sqn`、`sqnType`、`allowedClientIds`） | `state` を必須に、`allowPlain` をなくす |
| `GET /subscribers/{imsi}` | 個別の取得（鍵を除く） | 状態を含める |
| `PATCH /subscribers/{imsi}` | 変更（`amf`、`sqn`、`sqnType`、`allowedClientIds`）。`terminated` では 409 | 鍵と `allowPlain` を外す |
| `PUT /subscribers/{imsi}/state` | 状態の変更（本文: `state`、任意の `reason`）。`terminated` からは 409（`reinstate` を使う） | 新しく足す |
| `POST /subscribers/{imsi}/reinstate` | `terminated` から `inactive` に戻す（本文: `reason` 必須） | 新しく足す |
| `DELETE /subscribers/{imsi}` | 物理削除。`active` では 409 | 状態の検査を足す |
| `GET /subscribers/{imsi}/keys` | 鍵の読み出し。既定で無効（§8.4） | 既定で無効に |
| `GET /clients`、`GET /clients/{clientId}` | AV クライアントの一覧と詳細（証明書の期限、`networkName`、有効・無効） | 書き込みの口をなくす（§9.3） |
| `GET /av-server-certificate` | AV 用のサーバー証明書（PEM と期限） | 書き込みの口をなくす |
| `GET /audit-logs` | 監査ログ（新しい順、ページ送り） | — |

- もとの実装の `GET /logs`（メモリーの中の直近のログ）はなくす（§17 の B8）。ログは概要 §13 の仕組みで取りに行く。
- 加入者の応答の形（例）: `imsi`、`state`、`stateChangedAt`、`amf`、`sqn`、`sqnType`、`allowedClientIds`、`createdAt`、`updatedAt`。`stateChangedAt` は、課金レコードの状態の事実の漏れを台帳との突き合わせで補うとき（課金レコードの決定事項 13）の手がかりにする。

## 11. 主な流れ

### 11.1 認証（aka-radius から）

1. aka-radius が契約の GenerateAv を呼ぶ（1 ベクター）。
2. aka-vecgen はクライアントを識別し、形とネットワーク名を確かめ、払い出しの Lua で有無・許可・状態を確かめて SQN を進める。
3. `cred` を復号し、Milenage でベクターを作り（EAP-AKA' では CK'・IK' を導出し）、返す。
4. 拒否なら、理由をログに残して一般的な拒否を返す。

### 11.2 登録（一括投入・個別の登録）

1. aka-ossbss（一括投入のジョブか、システム管理者の画面）が aka-provisioner を通して `POST /admin/v2/subscribers` を呼ぶ。
2. aka-vecgen は鍵を暗号化して登録し、監査ログに残す（鍵は残さない。SQN・AMF・方式・状態を残す）。
3. 既にあれば 409。aka-ossbss は「既にある」として数える。

### 11.3 状態の変更と物理削除

- 状態の変更は aka-ossbss の操作から aka-provisioner を通して届く。aka-radius の状態とは独立に変わる（概要 §6.3）。
- 一括の物理削除は、`active` の IMSI を検証の段で除いてから（概要 §10.3）1 件ずつ `DELETE` を呼ぶ。

### 11.4 台帳との突き合わせ

- aka-ossbss が定期的に `GET /admin/v2/subscribers` で全件をたどり、台帳の有無と状態を比べる（概要 §6.4）。

## 12. 設定（環境変数）

| 名前 | 内容 | 既定 |
|---|---|---|
| `VECGEN_VALKEY_ADDR` / `VECGEN_VALKEY_PASSWORD` | Valkey | — |
| `VECGEN_KEK_FILE` | KEK のファイル | `/run/secrets/kek` |
| `VECGEN_AV_ADDR` / `VECGEN_AV_TLS_HOSTS` | 認証ベクターAPI の待ち受けとサーバー証明書の SAN | `:8443` / — |
| `VECGEN_ADMIN_ADDR` / `VECGEN_ADMIN_TLS_HOSTS` | 管理API の待ち受けとサーバー証明書の SAN | `:9443` / — |
| `VECGEN_ADMIN_CLIENTS_FILE` | 管理クライアントのピンのファイル | `/run/secrets/admin-clients` |
| `VECGEN_KEY_EXPORT` | 鍵の読み出しの API を有効にする | `false` |
| `VECGEN_AUDIT_MAX` | 監査ログの Stream の件数の上限 | 100000 |
| `VECGEN_AUDIT_DIR` | 監査ログの書き出し先（§13.2） | `/data/audit` |
| `VECGEN_LOG_LEVEL` | ログの段階 | `INFO` |

コマンド: `aka-vecgen serve`（既定）、`gen-kek`、`rotate-kek`、`client`（AV クライアントの登録・証明書の差し替え・有効と無効・ネットワーク名・削除）、`av-cert`、`admin-cert`、`fingerprint`、`subscriber`（試験と初めの確認のための個別の操作。鍵を標準入力から受ける）、`healthcheck`。

- コマンドは `docker compose exec` で、動いているコンテナの中で使う（Valkey と KEK に届くため）。使ったことは監査ログに残す（操作者は `cli`）。

## 13. ログと監査ログ

### 13.1 ログ

- JSON（`log/slog`）で標準出力に出す。`event_id` と `trace_id` を付ける（例: `AV_ISSUED`、`AV_REJECTED`（`reason` つき）、`AV_FAILED`、`ADMIN_REQUEST`、`ADMIN_CLIENTS_RELOADED`、`KEK_MISMATCH`）。
- 認証ベクターの払い出しは、IMSI・クライアント ID・認証タイプ・再同期の有無・`trace_id` を残す。IMSI はマスクしない（決定事項 26）。
- Ki・OPc・CK・IK・CK'・IK'・XRES・KEK はログに出さない。
- 集め方は概要 §13 の仕組み（ノードで圧縮して 2 週間、監視用の PC が取りに行く）による。

### 13.2 監査ログ

- 残すもの: 加入者の登録・変更・状態の変更・Terminated からの戻し・削除、鍵の読み出し、AV クライアントとサーバー証明書の操作（コマンド）、KEK の入れ替え、管理クライアントの読み直し。項目はもとの実装と同じ（日時、操作者、管理クライアント、操作、対象、変更の内容、`trace_id`）に、理由（状態の変更）を足す。
- 置き場所は 2 つ: Valkey の Stream（件数の上限つき。管理API で見る）と、日ごとの追記だけのファイル（`VECGEN_AUDIT_DIR` の `audit-YYYYMMDD.jsonl`）。ファイルは日が変わったら圧縮し、監視用の PC が取りに行く（概要 §13。Stream から押し出される前に残すため。§17 の B9）。ノードでは 2 週間持つ。
- 一括投入の行ごとの操作は、`trace_id` にジョブの ID が入る（概要 §10.4）。

## 14. 配備

- compose に aka-vecgen と Valkey を置く。データ面のノードで aka-radius と並べる。
- aka-radius と共有する Docker のネットワーク（external）に、aka-vecgen の認証ベクターAPI だけを出す。Valkey は出さない。
- 管理API はサービス用の WireGuard のアドレスにだけ結び付ける（`ports` のバインド先と nftables の `DOCKER-USER`。概要 §5.3）。
- KEK と管理クライアントのピンのファイルは Docker の secrets で渡す。ピンのファイルを書き換えたら `docker compose kill -s HUP aka-vecgen` で読み直す。
- healthcheck は、もとの実装と同じく待ち受けに TCP でつなげるかを確かめる。

## 15. 試験

| 層 | 内容 |
|---|---|
| 単体 | Milenage（TS 35.208 の 20 件）、AKA' の鍵の導出（RFC 5448 の 4 件）、SQN の方式、再同期、状態の移り方の規則、暗号化（違う KEK・違う AAD の行は復号できない、`cfg:kek_check`）、管理クライアントのピンのファイルの読み直し（形の誤りで前の設定が残る） |
| 結合（実際の Valkey） | 払い出しの Lua（状態、無効のクライアント、同時の要求で SQN が重ならない）、管理API（状態の変更と戻し、Active の削除の拒否、Terminated の変更の拒否、一括取得、一覧のカーソル）、`rotate-kek`（途中で止めてやり直す） |
| 適合試験 | 契約 §14 の C1〜C11 を CI で走らせる（aka-mvpset の `conformance/av-api/` を固定のコミットで取る） |
| 規模 | 加入者 20 万件を入れ、毎秒 100 要求で p99 200 ミリ秒（契約 §11.1）、一覧の全件のたどりの時間、Valkey のメモリー（概要 §16.1） |

## 16. 進め方（案）

| 段階 | 内容 | 終わりの確かめ |
|---|---|---|
| 1 | リポジトリ `aka-vecgen` を作り、aka-only-server の履歴ごと移す。改名だけ（module パス、コマンド、環境変数の接頭辞、Docker のネットワーク名、イメージ名、文書） | 今の CI が通る |
| 2-1 | 状態と払い出しの Lua の変更、認証ベクターAPI を契約に合わせる（V1〜V6）、平文HTTP をなくす | 単体・結合、適合試験 |
| 2-2 | 鍵の暗号化、KEK（起動の確認、`gen-kek`、`rotate-kek`） | 単体・結合 |
| 2-3 | 管理API 2.0.0（状態の口、一括取得、鍵の口の既定の無効、書き込みの口をコマンドへ、`/logs` をなくす）、ピンのファイルと `SIGHUP`、監査ログの書き出し | 結合、aka-provisioner との契約の試験 |
| 2-4 | 運用ガイド（導入、KEK とバックアップ、SQN の方式の指針、鍵を誤ったときの登録し直し）、README | 手元の compose、simwifi で aka-radius から認証 |

- 2-1 は aka-radius の改修（契約 §16.2）と同じ時期に行い、aka-radius との通しを早く確かめる。

## 17. 確認事項（2026-10-25 にすべて推奨案で合意。§3.2 の決定事項 1〜11）

| # | 事項 | 推奨 | 理由 |
|---|---|---|---|
| B1 | 名前（段階 1） | module パス `github.com/oyaguma3/aka-vecgen`、コマンド `aka-vecgen`、環境変数の接頭辞 `VECGEN_` | もとの `AKA_` は aka-radius など他のノードの名前と紛れる。radsec-ca の `CA_` と同じく、ノードを表す短い接頭辞にする |
| B2 | 状態の値と口 | 値は小文字の `active` / `inactive` / `terminated`。変更は `PUT …/state`、戻しは `POST …/reinstate`（理由が必須）。登録で状態を必須にする（§7、§10.2） | 本PoC の Provisioning API 0.4.0 の `active` / `suspended` と同じ書き方。戻しを別の口にすると、システム管理者だけに許す操作を aka-ossbss と aka-provisioner で見分けやすい。aka-radius も同じ値と口にそろえる（aka-radius の設計概要で確かめる） |
| B3 | 鍵の暗号化の形 | Ki ‖ OPc を 1 つの暗号文にし、AAD は IMSI を含む文字列。起動の確認は `cfg:kek_check` の復号。`rotate-kek` は止めて行い、行ごとの KEK の識別子でやり直せるようにする（§8） | 1 つにすると Ki と OPc の取り違えが起きない。radsec-ca は起動のときに全 CA を復号するが、20 万件では重いので確認用の値で代える |
| B4 | 登録の後の鍵の変更 | API を作らない。誤りは `inactive` → 削除 → 登録し直しで直す。鍵の読み出しは `VECGEN_KEY_EXPORT=true` のときだけ（§8.4） | 鍵の通り道を登録の 1 つに限る（概要 §12.2）。同じ IMSI で鍵が変わるのは誤りの直しくらいで、まれ |
| B5 | 平文HTTP（契約の決定事項 5） | 平文HTTP のリスナーと加入者の `allowPlain` をなくす | 契約の外で、IMSI ごとの許可クライアントが効かない。データ面の同じノードの aka-radius も mTLS でつなぐ |
| B6 | AV クライアントと AV 用のサーバー証明書の管理 | 書き込みはノードの上のコマンドで行い、管理API は読み出しだけにする（§9.3） | MVP の AV クライアントは aka-radius の 1 つで、変えるのは証明書の更新くらい。aka-ossbss に画面と権限を作るより小さく、鍵に準じる設定を管理面から変えられないようにできる。aka-ossbss は許可クライアントを選ぶために一覧を読む |
| B7 | 管理クライアントのピンの読み直し | ファイル（Docker の secrets）にして `SIGHUP` で読み直す。同じ識別名に新旧 2 つを書ける（§10.1） | 概要 §12.3。環境変数は再起動しないと変わらない。aka-radius・aka-provisioner・radsec-ca も同じ作りにそろえる（各設計概要で確かめる） |
| B8 | メモリーの中のログの口（`GET /logs`） | なくす | もとは aka-only-server の画面のためのもので、MVP の画面は aka-vecgen のログを見せない。ログは概要 §13 の仕組みで集める |
| B9 | 監査ログの書き出し（概要 §13） | Stream に加えて、日ごとの追記だけの JSONL のファイルに書き、監視用の PC が取りに行く（§13.2） | Stream は件数の上限で押し出される。標準出力のログと分けておくと、ログの経路（aka-radius の設計概要の決定事項 10 で Fluent Bit に決めた）がどうなっても監査ログを確実に残せる |
| B10 | 503 を返す場合 | Valkey に届かないときは 503 `NF_CONGESTION`、他の中の誤りは 500 `SYSTEM_FAILURE` | どちらも呼び出し側では一時的な誤りだが、ログと監視で「保存先の障害」と「作りの誤り」を分けられる |
| B11 | 一括投入の重複と冪等 | aka-vecgen は `Idempotency-Key` を扱わない。登録の 409・削除の 404 で「既にある」「ない」を返し、再送の判定は aka-provisioner に任せる（§10.1） | 再送の判定は aka-provisioner に既にあり（同じ管理クライアントからの 24 時間の再送）、下流の 2 か所で持つ意味がない |
