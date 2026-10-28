package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestSubscriberKeys(t *testing.T) {
	const ki, opc = "465b5ce8b199b49faa5f0a2ee238a6bc", "cd63cb71954a9f4e48a5994e37a02baf"
	tests := []struct {
		name          string
		stdin         string
		kiArg, opcArg string
		wantErr       bool
	}{
		{name: "引数", kiArg: ki, opcArg: opc},
		{name: "標準入力の 1 行", stdin: ki + " " + opc + "\n"},
		{name: "標準入力の大文字と前後の空白", stdin: "  " + strings.ToUpper(ki) + "\t" + opc},
		{name: "引数があれば標準入力を読まない", stdin: "garbage", kiArg: ki, opcArg: opc},
		{name: "片方だけの引数", kiArg: ki, wantErr: true},
		{name: "標準入力が空", wantErr: true},
		{name: "標準入力の値が 1 つ", stdin: ki, wantErr: true},
		{name: "標準入力の値が 3 つ", stdin: ki + " " + opc + " " + opc, wantErr: true},
		{name: "桁が違う", stdin: ki + " " + opc[:30], wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKi, gotOPc, err := subscriberKeys(strings.NewReader(tt.stdin), tt.kiArg, tt.opcArg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(gotKi) != ki || hex.EncodeToString(gotOPc) != opc {
				t.Errorf("got %x %x", gotKi, gotOPc)
			}
		})
	}
}
