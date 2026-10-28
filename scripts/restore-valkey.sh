#!/bin/sh
# backup-valkey.sh で取ったスナップショットから Valkey を戻す（運用ガイド 9.3）。今のデータは消える。
# compose.yaml のあるディレクトリで実行する。終わったら docker compose up -d で起動する。
#
#   scripts/restore-valkey.sh backups/valkey-20261028.rdb
#
# Valkey は AOF が有効だと、AOF がないときにスナップショットを読まずに空で始まる。
# そこで、AOF を切った一時の Valkey でスナップショットを読み込み、CONFIG SET appendonly yes で
# 読み込んだ中身から AOF を作り直してから止める（2026-10-28 に手元で確かめた）。
set -eu

in=${1:?usage: scripts/restore-valkey.sh <スナップショットのファイル>}
if [ ! -f "$in" ]; then
	echo "restore-valkey: $in がない" >&2
	exit 1
fi
src=$(cd "$(dirname "$in")" && pwd)/$(basename "$in")

docker compose stop aka-vecgen valkey

# compose の valkey のサービス（ボリューム valkey-data を /data に付けたもの）で、一時の Valkey を動かす
docker compose run --rm --no-deps -T -v "$src":/restore/dump.rdb:ro valkey sh -euc '
	rm -rf /data/* /data/.[!.]*
	cp /restore/dump.rdb /data/dump.rdb
	valkey-server --dir /data --appendonly no --daemonize yes --save ""
	until valkey-cli PING 2> /dev/null | grep -q PONG; do sleep 1; done
	valkey-cli CONFIG SET appendonly yes > /dev/null
	until valkey-cli INFO persistence | grep -q "^aof_rewrite_in_progress:0" &&
		valkey-cli INFO persistence | grep -q "^aof_rewrite_scheduled:0"; do sleep 1; done
	valkey-cli INFO persistence | grep -q "^aof_last_bgrewrite_status:ok"
	echo "restore-valkey: keys=$(valkey-cli DBSIZE)"
	valkey-cli SHUTDOWN NOSAVE > /dev/null 2>&1 || true
	while valkey-cli PING > /dev/null 2>&1; do sleep 1; done
	chown -R valkey:valkey /data
'
echo "restore-valkey: 戻した。docker compose up -d で起動する（KEK はスナップショットを取ったときのもの）"
