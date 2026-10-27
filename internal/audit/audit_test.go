package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/store"
)

type fakeStream struct {
	entries []store.AuditEntry
	err     error
}

func (f *fakeStream) AppendAudit(_ context.Context, e store.AuditEntry, _ int64) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.entries = append(f.entries, e)
	return "1700000000000-0", nil
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		r = zr
	}
	var out []map[string]any
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestRecord(t *testing.T) {
	dir := t.TempDir()
	stream := &fakeStream{}
	var logs bytes.Buffer
	// 2026-10-27 23:30 UTC は日本時間で 10-28 の 8:30
	at := time.Date(2026, 10, 27, 23, 30, 0, 0, time.UTC)
	r := &Recorder{Stream: stream, MaxLen: 10, Files: NewFiles(dir, 14), Log: slog.New(slog.NewJSONHandler(&logs, nil)), now: func() time.Time { return at }}

	r.Record(t.Context(), store.AuditEntry{Operator: "op-1", MgmtClient: "prov", Action: "subscriber.create", Target: "001010000000001",
		Detail: `{"state":"active"}`, TraceID: "trace-1"})
	r.Record(t.Context(), store.AuditEntry{Operator: "cli", MgmtClient: "cli", Action: "client.update", Target: "3", Detail: "not json"})

	if len(stream.entries) != 2 {
		t.Fatalf("stream got %d entries", len(stream.entries))
	}
	lines := readLines(t, filepath.Join(dir, "audit-20261028.jsonl"))
	if len(lines) != 2 {
		t.Fatalf("file has %d lines", len(lines))
	}
	if lines[0]["time"] != "2026-10-28T08:30:00+09:00" || lines[0]["action"] != "subscriber.create" || lines[0]["mgmtClient"] != "prov" ||
		lines[0]["traceId"] != "trace-1" || lines[0]["streamId"] != "1700000000000-0" {
		t.Errorf("line 0 = %v", lines[0])
	}
	if d, ok := lines[0]["detail"].(map[string]any); !ok || d["state"] != "active" {
		t.Errorf("detail is not kept as JSON: %v", lines[0]["detail"])
	}
	if lines[1]["detail"] != "not json" {
		t.Errorf("non-JSON detail = %v", lines[1]["detail"])
	}
	if !strings.Contains(logs.String(), `"event_id":"AUDIT"`) {
		t.Errorf("log = %s", logs.String())
	}
}

func TestRecordWriteErrors(t *testing.T) {
	// 書けなくても止めず、ERROR のログを出す
	var logs bytes.Buffer
	r := &Recorder{Stream: &fakeStream{err: errors.New("valkey down")}, Files: NewFiles(filepath.Join(t.TempDir(), "missing"), 14),
		Log: slog.New(slog.NewJSONHandler(&logs, nil))}
	r.Record(t.Context(), store.AuditEntry{Action: "subscriber.delete"})
	out := logs.String()
	if strings.Count(out, `"event_id":"AUDIT_WRITE_ERR"`) != 2 || !strings.Contains(out, `"to":"stream"`) || !strings.Contains(out, `"to":"file"`) {
		t.Errorf("log = %s", out)
	}
	if NewFiles("", 14) != nil {
		t.Error("NewFiles(\"\") should be nil")
	}
}

func TestMaintain(t *testing.T) {
	dir := t.TempDir()
	f := NewFiles(dir, 14)
	now := time.Date(2026, 10, 28, 3, 0, 0, 0, jst)
	write := func(name, content string, mtime time.Time) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	write("audit-20261028.jsonl", `{"a":1}`+"\n", now)                       // 今日: そのまま
	write("audit-20261027.jsonl", `{"a":2}`+"\n", now.Add(-time.Hour))       // 昨日: 圧縮する
	write("audit-20261026.jsonl", `{"a":3}`+"\n", now.Add(-5*time.Minute))   // 書いたばかり: まだ圧縮しない
	write("audit-20261014.jsonl.gz", "old", now.Add(-14*24*time.Hour))       // 14 日前: 残す
	write("audit-20261013.jsonl.gz", "older", now.Add(-15*24*time.Hour))     // 15 日前: 消す
	write("audit-20261001.jsonl", `{"a":4}`+"\n", now.Add(-27*24*time.Hour)) // 古い圧縮前: 消す
	write("other.txt", "x", now.Add(-30*24*time.Hour))                       // 関係のないファイル: 触らない

	if err := f.Maintain(now); err != nil {
		t.Fatal(err)
	}
	var names []string
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		names = append(names, e.Name())
	}
	want := []string{"audit-20261014.jsonl.gz", "audit-20261026.jsonl", "audit-20261027.jsonl.gz", "audit-20261028.jsonl", "other.txt"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("files = %v, want %v", names, want)
	}
	if lines := readLines(t, filepath.Join(dir, "audit-20261027.jsonl.gz")); len(lines) != 1 || lines[0]["a"] != float64(2) {
		t.Errorf("compressed content = %v", lines)
	}
	if err := NewFiles(filepath.Join(dir, "none"), 14).Maintain(now); err == nil {
		t.Error("Maintain on a missing directory: want error")
	}
}
