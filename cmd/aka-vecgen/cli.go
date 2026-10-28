package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

var imsiPattern = regexp.MustCompile(`^[0-9]{5,15}$`)

func subscriberCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: aka-vecgen subscriber add|show|del [options]")
	}
	fs := flag.NewFlagSet("subscriber "+args[0], flag.ExitOnError)
	imsi := fs.String("imsi", "", "IMSI（5〜15 桁の数字）")

	switch args[0] {
	case "add":
		ki := fs.String("ki", "", "Ki（16進 32 桁）。-ki と -opc を省くと、標準入力の 1 行（Ki OPc）から読む")
		opc := fs.String("opc", "", "OPc（16進 32 桁）")
		sqn := fs.String("sqn", "000000000000", "SQN の初期値（16進 12 桁）")
		amf := fs.String("amf", "8000", "AMF（16進 4 桁）")
		sqnType := fs.String("sqn-type", string(aka.SQNInc32), "SQN 増加タイプ（inc1 / inc32 / inc33）")
		state := fs.String("state", string(store.StateActive), "状態（active / inactive / terminated。terminated は inactive で登録してから変える）")
		clients := fs.String("clients", "", "許可クライアントID（カンマ区切り）")
		operator := operatorFlag(fs)
		fs.Parse(args[1:])

		sub := store.Subscriber{IMSI: *imsi, SQNType: aka.SQNType(*sqnType), State: store.State(*state)}
		if !imsiPattern.MatchString(sub.IMSI) {
			return errors.New("-imsi must be 5 to 15 digits")
		}
		if !sub.State.Valid() {
			return errors.New("-state must be active, inactive or terminated")
		}
		terminate := sub.State == store.StateTerminated
		if terminate {
			sub.State = store.StateInactive
		}
		var err error
		if sub.Ki, sub.OPc, err = subscriberKeys(os.Stdin, *ki, *opc); err != nil {
			return err
		}
		sqnBytes, err := hexBytes("-sqn", *sqn, 6)
		if err != nil {
			return err
		}
		for _, b := range sqnBytes {
			sub.SQN = sub.SQN<<8 | uint64(b)
		}
		amfBytes, err := hexBytes("-amf", *amf, 2)
		if err != nil {
			return err
		}
		sub.AMF = uint16(amfBytes[0])<<8 | uint16(amfBytes[1])
		if !sub.SQNType.Valid() {
			return errors.New("-sqn-type must be inc1, inc32 or inc33")
		}
		for part := range strings.SplitSeq(*clients, ",") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			id, err := strconv.ParseInt(part, 10, 64)
			if err != nil || id < 1 {
				return fmt.Errorf("-clients: bad client id %q", part)
			}
			sub.AllowedClientIDs = append(sub.AllowedClientIDs, id)
		}

		_, st, a, err := openForCommand(ctx, *operator)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.CreateSubscriber(ctx, sub); err != nil {
			return err
		}
		a.record(ctx, "subscriber.create", sub.IMSI, map[string]any{
			"state": sub.State, "sqn": fmt.Sprintf("%012x", sub.SQN), "amf": fmt.Sprintf("%04x", sub.AMF), "sqnType": sub.SQNType, "allowedClientIds": sub.AllowedClientIDs,
		})
		if terminate {
			if _, _, err := st.SetState(ctx, sub.IMSI, store.StateTerminated); err != nil {
				return fmt.Errorf("subscriber %s was added as inactive, but setting it terminated failed: %w", sub.IMSI, err)
			}
			a.record(ctx, "subscriber.state", sub.IMSI, map[string]any{"state": change{store.StateInactive, store.StateTerminated}})
			sub.State = store.StateTerminated
		}
		fmt.Printf("subscriber %s added (state=%s)\n", sub.IMSI, sub.State)
		return nil

	case "show":
		fs.Parse(args[1:])
		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		sub, err := st.GetSubscriber(ctx, *imsi)
		if err != nil {
			return err
		}
		// Ki と OPc は表示しない。
		fmt.Printf("imsi:        %s\n", sub.IMSI)
		fmt.Printf("state:       %s\n", sub.State)
		fmt.Printf("sqn:         %012x\n", sub.SQN)
		fmt.Printf("amf:         %04x\n", sub.AMF)
		fmt.Printf("sqn-type:    %s\n", sub.SQNType)
		fmt.Printf("clients:     %v\n", sub.AllowedClientIDs)
		fmt.Printf("created-at:  %s\n", sub.CreatedAt.Format(time.RFC3339))
		return nil

	case "del":
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		_, st, a, err := openForCommand(ctx, *operator)
		if err != nil {
			return err
		}
		defer st.Close()
		before, err := st.GetSubscriber(ctx, *imsi)
		if err != nil {
			return err
		}
		if err := st.DeleteSubscriber(ctx, *imsi); err != nil {
			return err
		}
		a.record(ctx, "subscriber.delete", *imsi, map[string]any{"state": before.State})
		fmt.Printf("subscriber %s deleted\n", *imsi)
		return nil
	}
	return fmt.Errorf("unknown subscriber command %q", args[0])
}

// subscriberKeys は Ki と OPc を引数か標準入力から読む。
// 本物の鍵を引数に書くと、シェルの履歴とホストのプロセスの一覧に残るので、標準入力から渡せるようにする（設計概要 §12）。
func subscriberKeys(stdin io.Reader, ki, opc string) ([]byte, []byte, error) {
	switch {
	case ki == "" && opc == "":
		data, err := io.ReadAll(io.LimitReader(stdin, 1024))
		if err != nil {
			return nil, nil, err
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return nil, nil, errors.New("stdin must be one line: <Ki> <OPc>")
		}
		ki, opc = fields[0], fields[1]
	case ki == "" || opc == "":
		return nil, nil, errors.New("-ki and -opc must be given together (or both omitted to read from stdin)")
	}
	kiB, err := hexBytes("Ki", ki, 16)
	if err != nil {
		return nil, nil, err
	}
	opcB, err := hexBytes("OPc", opc, 16)
	if err != nil {
		return nil, nil, err
	}
	return kiB, opcB, nil
}

func fingerprintCommand() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	cert, err := certs.ParsePEM(data)
	if err != nil {
		return err
	}
	fmt.Println(certs.Fingerprint(cert))
	return nil
}

func hexBytes(name, v string, size int) ([]byte, error) {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%s must be %d hex digits", name, size*2)
	}
	return b, nil
}

func writeOutput(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, perm)
}
