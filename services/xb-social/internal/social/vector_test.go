package social

import "testing"

func TestNotifierVectorWords(t *testing.T) {
	var gotX uint64
	var got []uint32
	n := &Notifier{Emit: func(x uint64, w []uint32) { gotX, got = x, w }}
	n.Apply(Push{XUID: "0009000000000001", Bits: PendingList1})
	if gotX != 0x0009000000000001 || len(got) != 2 || got[0]&0xff != 1 || got[1] != BitList {
		t.Fatalf("list push %x %x", gotX, got)
	}
	v1 := got[0] >> 8
	n.Apply(Push{XUID: "0009000000000001", Bits: PendingPresent})
	if len(got) != 3 || got[2]&0xff != 0x88 || got[2]>>8 <= v1 {
		t.Fatalf("presence word %x (list version %d)", got, v1)
	}
	w := n.Take("0009000000000001", BitList)
	if w[1] != 0 || w[0]>>8 <= v1 {
		t.Fatalf("take must clear the bit with a higher version: %x", w)
	}
	again := n.Take("0009000000000001", BitList)
	if again[0] != w[0] {
		t.Fatal("clearing an already clear bit must not bump the version")
	}
	n.Apply(Push{XUID: "0009000000000001", Bits: PendingInvite})
	if got[1] != BitInvite {
		t.Fatalf("invite bit %x", got)
	}
}
