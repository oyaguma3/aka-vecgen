package aka

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func sqnFromHex(t *testing.T, s string) uint64 {
	t.Helper()
	return binary.BigEndian.Uint64(append([]byte{0, 0}, mustHex(t, s)...))
}

// 3GPP TS 35.208 4.3 のテストセット。
var milenageTestSets = []struct {
	set                                int
	k, rand, sqn, amf, opc             string
	f1, f1star, f2, f3, f4, f5, f5star string
}{
	{set: 1, k: "465b5ce8b199b49faa5f0a2ee238a6bc", rand: "23553cbe9637a89d218ae64dae47bf35", sqn: "ff9bb4d0b607", amf: "b9b9", opc: "cd63cb71954a9f4e48a5994e37a02baf",
		f1: "4a9ffac354dfafb3", f1star: "01cfaf9ec4e871e9", f2: "a54211d5e3ba50bf", f3: "b40ba9a3c58b2a05bbf0d987b21bf8cb", f4: "f769bcd751044604127672711c6d3441", f5: "aa689c648370", f5star: "451e8beca43b"},
	{set: 2, k: "0396eb317b6d1c36f19c1c84cd6ffd16", rand: "c00d603103dcee52c4478119494202e8", sqn: "fd8eef40df7d", amf: "af17", opc: "53c15671c60a4b731c55b4a441c0bde2",
		f1: "5df5b31807e258b0", f1star: "a8c016e51ef4a343", f2: "d3a628ed988620f0", f3: "58c433ff7a7082acd424220f2b67c556", f4: "21a8c1f929702adb3e738488b9f5c5da", f5: "c47783995f72", f5star: "30f1197061c1"},
	{set: 3, k: "fec86ba6eb707ed08905757b1bb44b8f", rand: "9f7c8d021accf4db213ccff0c7f71a6a", sqn: "9d0277595ffc", amf: "725c", opc: "1006020f0a478bf6b699f15c062e42b3",
		f1: "9cabc3e99baf7281", f1star: "95814ba2b3044324", f2: "8011c48c0c214ed2", f3: "5dbdbb2954e8f3cde665b046179a5098", f4: "59a92d3b476a0443487055cf88b2307b", f5: "33484dc2136b", f5star: "deacdd848cc6"},
	{set: 4, k: "9e5944aea94b81165c82fbf9f32db751", rand: "ce83dbc54ac0274a157c17f80d017bd6", sqn: "0b604a81eca8", amf: "9e09", opc: "a64a507ae1a2a98bb88eb4210135dc87",
		f1: "74a58220cba84c49", f1star: "ac2cc74a96871837", f2: "f365cd683cd92e96", f3: "e203edb3971574f5a94b0d61b816345d", f4: "0c4524adeac041c4dd830d20854fc46b", f5: "f0b9c08ad02e", f5star: "6085a86c6f63"},
	{set: 5, k: "4ab1deb05ca6ceb051fc98e77d026a84", rand: "74b0cd6031a1c8339b2b6ce2b8c4a186", sqn: "e880a1b580b6", amf: "9f07", opc: "dcf07cbd51855290b92a07a9891e523e",
		f1: "49e785dd12626ef2", f1star: "9e85790336bb3fa2", f2: "5860fc1bce351e7e", f3: "7657766b373d1c2138f307e3de9242f9", f4: "1c42e960d89b8fa99f2744e0708ccb53", f5: "31e11a609118", f5star: "fe2555e54aa9"},
	{set: 6, k: "6c38a116ac280c454f59332ee35c8c4f", rand: "ee6466bc96202c5a557abbeff8babf63", sqn: "414b98222181", amf: "4464", opc: "3803ef5363b947c6aaa225e58fae3934",
		f1: "078adfb488241a57", f1star: "80246b8d0186bcf1", f2: "16c8233f05a0ac28", f3: "3f8c7587fe8e4b233af676aede30ba3b", f4: "a7466cc1e6b2a1337d49d3b66e95d7b4", f5: "45b0f69ab06c", f5star: "1f53cd2b1113"},
	{set: 7, k: "2d609d4db0ac5bf0d2c0de267014de0d", rand: "194aa756013896b74b4a2a3b0af4539e", sqn: "6bf69438c2e4", amf: "5f67", opc: "c35a0ab0bcbfc9252caff15f24efbde0",
		f1: "bd07d3003b9e5cc3", f1star: "bcb6c2fcad152250", f2: "8c25a16cd918a1df", f3: "4cd0846020f8fa0731dd47cbdc6be411", f4: "88ab80a415f15c73711254a1d388f696", f5: "7e6455f34cf3", f5star: "dc6dd01e8f15"},
	{set: 8, k: "a530a7fe428fad1082c45eddfce13884", rand: "3a4c2b3245c50eb5c71d08639395764d", sqn: "f63f5d768784", amf: "b90e", opc: "27953e49bc8af6dcc6e730eb80286be3",
		f1: "53761fbd679b0bad", f1star: "21adfd334a10e7ce", f2: "a63241e1ffc3e5ab", f3: "10f05bab75a99a5fbb98a9c287679c3b", f4: "f9ec0865eb32f22369cade40c59c3a44", f5: "88196c47986f", f5star: "c987a3d23115"},
	{set: 9, k: "d9151cf04896e25830bf2e08267b8360", rand: "f761e5e93d603feb730e27556cb8a2ca", sqn: "47ee0199820a", amf: "9113", opc: "c4c93effe8a08138c203d4c27ce4e3d9",
		f1: "66cc4be44862af1f", f1star: "7a4b8d7a8753f246", f2: "4a90b2171ac83a76", f3: "71236b7129f9b22ab77ea7a54c96da22", f4: "90527ebaa5588968db41727325a04d9e", f5: "82a0f5287a71", f5star: "527dbf41f35f"},
	{set: 10, k: "a0e2971b6822e8d354a18cc235624ecb", rand: "08eff828b13fdb562722c65c7f30a9b2", sqn: "db5c066481e0", amf: "716b", opc: "82a26f22bba9e9488f949a10d98e9cc4",
		f1: "9485fe24621cb9f6", f1star: "bce325ce03e2e9b9", f2: "4bc2212d8624910a", f3: "08cef6d004ec61471a3c3cda048137fa", f4: "ed0318ca5deb9206272f6e8fa64ba411", f5: "a2f858aa9e5d", f5star: "74e76fbbec38"},
	{set: 11, k: "0da6f7ba86d5eac8a19cf563ac58642d", rand: "679ac4dbacd7d233ff9d6806f4149ce3", sqn: "6e2331d692ad", amf: "224a", opc: "0db1071f8767562ca43a0a64c41e8d08",
		f1: "2831d7ae9088e492", f1star: "9b2e16951135d523", f2: "6fc30fee6d123523", f3: "69b1cae7c7429d975e245cacb05a517c", f4: "74f24e8c26df58e1b38d7dcd4f1b7fbd", f5: "4c539a26e1fa", f5star: "07861e126928"},
	{set: 12, k: "77b45843c88e58c10d202684515ed430", rand: "4c47eb3076dc55fe5106cb2034b8cd78", sqn: "fe1a8731005d", amf: "ad25", opc: "d483afae562409a326b5bb0b20c4d762",
		f1: "08332d7e9f484570", f1star: "ed41b734489d5207", f2: "aefa357beac2a87a", f3: "908c43f0569cb8f74bc971e706c36c5f", f4: "c251df0d888dd9329bcf46655b226e40", f5: "30ff25cdadf6", f5star: "e84ed0d4677e"},
	{set: 13, k: "729b17729270dd87ccdf1bfe29b4e9bb", rand: "311c4c929744d675b720f3b7e9b1cbd0", sqn: "c85c4cf65916", amf: "5bb2", opc: "228c2f2f06ac3268a9e616ee16db4ba1",
		f1: "ff794fe2f827ebf8", f1star: "24fe4dc61e874b52", f2: "98dbbd099b3b408d", f3: "44c0f23c5493cfd241e48f197e1d1012", f4: "0c9fb81613884c2535dd0eabf3b440d8", f5: "5380d158cfe3", f5star: "87ac3b559fb6"},
	{set: 14, k: "d32dd23e89dc662354ca12eb79dd32fa", rand: "cf7d0ab1d94306950bf12018fbd46887", sqn: "484107e56a43", amf: "b5e6", opc: "d22a4b4180a5325708a5ff70d9f67ec7",
		f1: "cf19d62b6a809866", f1star: "5d269537e45e2ce6", f2: "af4a411e1139f2c2", f3: "5af86b80edb70df5292cc1121cbad50c", f4: "7f4d6ae7440e18789a8b75ad3f42f03a", f5: "217af49272ad", f5star: "900e101c677e"},
	{set: 15, k: "af7c65e1927221de591187a2c5987a53", rand: "1f0f8578464fd59b64bed2d09436b57a", sqn: "3d627b01418d", amf: "84f6", opc: "a4cf5c8155c08a7eff418e5443b98e55",
		f1: "c37cae7805642032", f1star: "68cd09a452d8db7c", f2: "7bffa5c2f41fbc05", f3: "3f8c3f3ccf7625bf77fc94bcfd22fd26", f4: "abcbae8fd46115e9961a55d0da5f2078", f5: "837fd7b74419", f5star: "56e97a6090b1"},
	{set: 16, k: "5bd7ecd3d3127a41d12539bed4e7cf71", rand: "59b75f14251c75031d0bcbac1c2c04c7", sqn: "a298ae8929dc", amf: "d056", opc: "76089d3c0ff3efdc6e36721d4fceb747",
		f1: "c3f25cd94309107e", f1star: "b0c8ba343665afcc", f2: "7e3f44c7591f6f45", f3: "d42b2d615e49a03ac275a5aef97af892", f4: "0b3f8d024fe6bfafaa982b8f82e319c2", f5: "5be11495525d", f5star: "4d6a34a1e4eb"},
	{set: 17, k: "6cd1c6ceb1e01e14f1b82316a90b7f3d", rand: "f69b78f300a0568bce9f0cb93c4be4c9", sqn: "b4fce5feb059", amf: "e4bb", opc: "a219dc37f1dc7d66738b5843c799f206",
		f1: "69a90869c268cb7b", f1star: "2e0fdcf9fd1cfa6a", f2: "70f6bdb9ad21525f", f3: "6edaf99e5bd9f85d5f36d91c1272fb4b", f4: "d61c853c280dd9c46f297baec386de17", f5: "1c408a858b3e", f5star: "aa4ae52daa30"},
	{set: 18, k: "b73a90cbcf3afb622dba83c58a8415df", rand: "b120f1c1a0102a2f507dd543de68281f", sqn: "f1e8a523a36d", amf: "471b", opc: "df0c67868fa25f748b7044c6e7c245b8",
		f1: "ebd70341bcd415b0", f1star: "12359f5d82220c14", f2: "479dd25c20792d63", f3: "66195dbed0313274c5ca7766615fa25e", f4: "66bec707eb2afc476d7408a8f2927b36", f5: "aefdaa5ddd99", f5star: "12ec2b87fbb1"},
	{set: 19, k: "5122250214c33e723a5dd523fc145fc0", rand: "81e92b6c0ee0e12ebceba8d92a99dfa5", sqn: "16f3b3f70fc2", amf: "c3ab", opc: "981d464c7c52eb6e5036234984ad0bcf",
		f1: "2a5c23d15ee351d5", f1star: "62dae3853f3af9d2", f2: "28d7b0f2a2ec3de5", f3: "5349fbe098649f948f5d2e973a81c00f", f4: "9744871ad32bf9bbd1dd5ce54e3e2e5a", f5: "ada15aeb7bb8", f5star: "d461bc15475d"},
	{set: 20, k: "90dca4eda45b53cf0f12d7c9c3bc6a89", rand: "9fddc72092c6ad036b6e464789315b78", sqn: "20f813bd4141", amf: "61df", opc: "cb9cccc4b9258e6dca4760379fb82581",
		f1: "09db94eab4f8149e", f1star: "a29468aa9775b527", f2: "a95100e2760952cd", f3: "b5f2da03883b69f96bf52e029ed9ac45", f4: "b4721368bc16ea67875c5598688bb0ef", f5: "83cfd54db913", f5star: "4f2039392ddc"},
}

func TestGenerate(t *testing.T) {
	for _, ts := range milenageTestSets {
		c := Credentials{
			Ki:  mustHex(t, ts.k),
			OPc: mustHex(t, ts.opc),
			AMF: binary.BigEndian.Uint16(mustHex(t, ts.amf)),
		}
		sqn := mustHex(t, ts.sqn)
		v, err := Generate(c, mustHex(t, ts.rand), sqnFromHex(t, ts.sqn))
		if err != nil {
			t.Fatalf("set %d: %v", ts.set, err)
		}

		// AUTN = (SQN xor AK) || AMF || MAC-A
		ak := mustHex(t, ts.f5)
		autn := make([]byte, 0, 16)
		for i := range 6 {
			autn = append(autn, sqn[i]^ak[i])
		}
		autn = append(autn, mustHex(t, ts.amf)...)
		autn = append(autn, mustHex(t, ts.f1)...)

		for _, f := range []struct {
			name      string
			got, want []byte
		}{
			{"XRES", v.XRES, mustHex(t, ts.f2)},
			{"CK", v.CK, mustHex(t, ts.f3)},
			{"IK", v.IK, mustHex(t, ts.f4)},
			{"AUTN", v.AUTN, autn},
		} {
			if !bytes.Equal(f.got, f.want) {
				t.Errorf("set %d: %s = %x, want %x", ts.set, f.name, f.got, f.want)
			}
		}
	}
}

// makeAUTS は端末側の処理を模して AUTS を作る。MAC-S は AMF を 0x0000 として計算する。
func makeAUTS(t *testing.T, c Credentials, rnd []byte, sqnMS uint64) []byte {
	t.Helper()
	m := newMilenage(c, rnd, sqnMS)
	auts, err := m.GenerateAUTS()
	if err != nil {
		t.Fatal(err)
	}
	return auts
}

func TestVerifyAUTS(t *testing.T) {
	for _, ts := range milenageTestSets {
		c := Credentials{
			Ki:  mustHex(t, ts.k),
			OPc: mustHex(t, ts.opc),
			AMF: binary.BigEndian.Uint16(mustHex(t, ts.amf)),
		}
		rnd := mustHex(t, ts.rand)
		sqnMS := sqnFromHex(t, ts.sqn)
		auts := makeAUTS(t, c, rnd, sqnMS)

		// AUTS の先頭 6 バイトは SQN_MS xor AK*（f5*）。
		sqn, aks := mustHex(t, ts.sqn), mustHex(t, ts.f5star)
		for i := range 6 {
			if auts[i] != sqn[i]^aks[i] {
				t.Fatalf("set %d: AUTS does not carry SQN_MS xor f5*", ts.set)
			}
		}

		got, err := VerifyAUTS(c, rnd, auts)
		if err != nil {
			t.Fatalf("set %d: %v", ts.set, err)
		}
		if got != sqnMS {
			t.Errorf("set %d: SQN_MS = %012x, want %012x", ts.set, got, sqnMS)
		}

		// MAC-S を 1 ビット壊すと検証に失敗する。
		bad := slices.Clone(auts)
		bad[13] ^= 0x01
		if _, err := VerifyAUTS(c, rnd, bad); !errors.Is(err, ErrAUTSInvalid) {
			t.Errorf("set %d: tampered MAC-S: err = %v, want ErrAUTSInvalid", ts.set, err)
		}
		// SQN 部分を壊しても検証に失敗する。
		bad = slices.Clone(auts)
		bad[0] ^= 0x80
		if _, err := VerifyAUTS(c, rnd, bad); !errors.Is(err, ErrAUTSInvalid) {
			t.Errorf("set %d: tampered SQN: err = %v, want ErrAUTSInvalid", ts.set, err)
		}
	}
}

func TestVerifyAUTSLength(t *testing.T) {
	c := Credentials{Ki: make([]byte, 16), OPc: make([]byte, 16)}
	if _, err := VerifyAUTS(c, make([]byte, 16), make([]byte, 13)); err == nil {
		t.Error("13-byte AUTS: want error")
	}
}

// RFC 5448 Appendix C のテストベクター。
var primeTestCases = []struct {
	name, networkName string
	autn, ck, ik      string
	ckPrime, ikPrime  string
}{
	{name: "Case 1", networkName: "WLAN", autn: "bb52e91c747ac3ab2a5c23d15ee351d5", ck: "5349fbe098649f948f5d2e973a81c00f", ik: "9744871ad32bf9bbd1dd5ce54e3e2e5a",
		ckPrime: "0093962d0dd84aa5684b045c9edffa04", ikPrime: "ccfc230ca74fcc96c0a5d61164f5a76c"},
	{name: "Case 2", networkName: "HRPD", autn: "bb52e91c747ac3ab2a5c23d15ee351d5", ck: "5349fbe098649f948f5d2e973a81c00f", ik: "9744871ad32bf9bbd1dd5ce54e3e2e5a",
		ckPrime: "3820f0277fa5f77732b1fb1d90c1a0da", ikPrime: "db94a0ab557ef6c9ab48619ca05b9a9f"},
	{name: "Case 3", networkName: "WLAN", autn: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", ck: "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", ik: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
		ckPrime: "cd4c8e5c68f57dd1d7d7dfd0c538e577", ikPrime: "3ece6b705dbbf7dfc459a11280c65524"},
	{name: "Case 4", networkName: "HRPD", autn: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", ck: "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", ik: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
		ckPrime: "8310a71ce6f754889613da8f64d5fb46", ikPrime: "5adf14360ae838192db23f6fcb7f8c76"},
}

func TestDerivePrime(t *testing.T) {
	for _, tc := range primeTestCases {
		v := Vector{AUTN: mustHex(t, tc.autn), CK: mustHex(t, tc.ck), IK: mustHex(t, tc.ik)}
		ckPrime, ikPrime := DerivePrime(v, tc.networkName)
		if want := mustHex(t, tc.ckPrime); !bytes.Equal(ckPrime, want) {
			t.Errorf("%s: CK' = %x, want %x", tc.name, ckPrime, want)
		}
		if want := mustHex(t, tc.ikPrime); !bytes.Equal(ikPrime, want) {
			t.Errorf("%s: IK' = %x, want %x", tc.name, ikPrime, want)
		}
	}
}

func TestSQNSequence(t *testing.T) {
	tests := []struct {
		typ  SQNType
		base uint64
		n    int
		want []uint64
	}{
		{SQNInc1, 0, 3, []uint64{1, 2, 3}},
		{SQNInc32, 0, 3, []uint64{32, 64, 96}},
		{SQNInc32, 5, 2, []uint64{37, 69}},
		// 1個目で IND を 1 進め、以降は IND を固定して SEQ だけ進める。
		{SQNInc33, 0, 3, []uint64{33, 65, 97}},
		// IND が 31 から 0 に回るときは SEQ に桁上げする。
		{SQNInc33, 31, 2, []uint64{64, 96}},
		// 48bit で折り返す。
		{SQNInc1, SQNMask, 2, []uint64{0, 1}},
		{SQNInc32, SQNMask - 31, 1, []uint64{0}},
	}
	for _, tt := range tests {
		got, err := tt.typ.Sequence(tt.base, tt.n)
		if err != nil {
			t.Fatalf("%s: %v", tt.typ, err)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s.Sequence(%d, %d) = %v, want %v", tt.typ, tt.base, tt.n, got, tt.want)
		}
		// inc33 のバッチ内では IND が変わらない。
		if tt.typ == SQNInc33 {
			for _, s := range got[1:] {
				if s&0x1f != got[0]&0x1f {
					t.Errorf("inc33: IND changed within batch: %v", got)
				}
			}
		}
	}
	if _, err := SQNType("bogus").Sequence(0, 1); err == nil {
		t.Error("unknown type: want error")
	}
}
