package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/kek"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// genKEKCommand は KEK（32 バイトの乱数を 16 進で書いたもの）を作る（設計概要 §8.3）。
// -out を省くか - なら標準出力に書く（コンテナの外のファイルに書き出すため）。ファイルは権限 0600 で作り、上書きしない。
func genKEKCommand(args []string) error {
	fs := flag.NewFlagSet("gen-kek", flag.ExitOnError)
	out := fs.String("out", "-", "KEK の出力先（- は標準出力）")
	fs.Parse(args)
	if *out == "-" {
		k, err := kek.Generate(os.Stdout)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "kek %s generated\n", k.ID())
		return nil
	}
	k, err := kek.GenerateFile(*out)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "kek %s written to %s\n", k.ID(), *out)
	return nil
}

// rotateKEKCommand は、加入者の鍵とサーバー証明書の秘密鍵を新しい KEK で暗号化し直す（設計概要 §8.3、確認事項 D3）。
// serve を止めてから行う（動いていれば断る）。途中で止まっても、同じファイルでやり直せば続きから終わらせる。
// 終わったら KEK のファイル（VECGEN_KEK_FILE）を新しいものに置き換えてから serve を起動する。
func rotateKEKCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rotate-kek", flag.ExitOnError)
	oldFile := fs.String("old", "", "今の KEK のファイル")
	newFile := fs.String("new", "", "新しい KEK のファイル")
	fs.Parse(args)
	if *oldFile == "" || *newFile == "" {
		return fmt.Errorf("-old and -new are required")
	}
	oldK, err := kek.Load(*oldFile)
	if err != nil {
		return err
	}
	newK, err := kek.Load(*newFile)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	octx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := store.Open(octx, store.Options{Addr: cfg.ValkeyAddr, Password: cfg.ValkeyPassword})
	if err != nil {
		return err
	}
	defer st.Close()

	start := time.Now()
	res, err := st.RotateKEK(ctx, oldK, newK, func(done, total int) {
		fmt.Fprintf(os.Stderr, "\rsubscribers %d/%d", done, total)
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("rotate-kek %s -> %s: %w", oldK.ID(), newK.ID(), err)
	}
	fmt.Printf("kek rotated %s -> %s in %s: subscribers rotated=%d already-new=%d invalid=%d, server certificates=%d\n",
		oldK.ID(), newK.ID(), time.Since(start).Round(time.Millisecond), res.Rotated, res.AlreadyNew, res.Invalid, res.Certificates)
	if res.Invalid > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d subscribers have unreadable credentials (rows written before the KEK, or broken); re-register them\n", res.Invalid)
	}
	fmt.Fprintln(os.Stderr, "replace the KEK file (VECGEN_KEK_FILE) with the new one, then start aka-vecgen")
	return nil
}
