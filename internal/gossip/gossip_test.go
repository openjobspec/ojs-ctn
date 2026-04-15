package gossip

import (
	"strings"
	"testing"
)

var alice, bob = "alice", "bob"

func helloFrom(peer string) Msg {
	return Msg{Type: MsgHello, Peer: peer, Algs: []string{"ed25519"}}
}

func TestStep_RejectsMessagesBeforeHello(t *testing.T) {
	s := NewState(alice)
	if _, err := Step(s, Msg{Type: MsgHave, Peer: bob}); err == nil {
		t.Error("expected pre-Hello rejection")
	}
}

func TestStep_HelloHandshakeAndAlgs(t *testing.T) {
	s := NewState(alice)
	out, err := Step(s, helloFrom(bob))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Type != MsgHello {
		t.Errorf("expected single Hello reply, got %+v", out)
	}
	if !s.Peers[bob].HelloSeen {
		t.Error("HelloSeen not set")
	}
}

func TestStep_HelloEchoesOurHaves(t *testing.T) {
	s := NewState(alice)
	var log LogID
	log[0] = 0xab
	s.OurBest[log] = 42
	s.OurHashes[log] = [32]byte{0x99}
	out, _ := Step(s, helloFrom(bob))
	if len(out) != 2 {
		t.Fatalf("expected Hello + Have, got %d", len(out))
	}
	if out[1].Type != MsgHave || out[1].Size != 42 {
		t.Errorf("expected Have(size=42), got %+v", out[1])
	}
}

func TestStep_DuplicateHelloRejected(t *testing.T) {
	s := NewState(alice)
	_, _ = Step(s, helloFrom(bob))
	if _, err := Step(s, helloFrom(bob)); err == nil {
		t.Error("expected duplicate-Hello error")
	}
}

func TestStep_HavePeerAheadTriggersWant(t *testing.T) {
	s := NewState(alice)
	_, _ = Step(s, helloFrom(bob))
	var log LogID
	log[0] = 1
	out, err := Step(s, Msg{Type: MsgHave, Peer: bob, Log: log, Size: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Type != MsgWant || out[0].From != 0 {
		t.Errorf("expected Want{from:0}, got %+v", out)
	}
	if s.Peers[bob].BestSTH[log] != 100 {
		t.Error("BestSTH not updated")
	}
	if s.Peers[bob].InflightReq[log] != 100 {
		t.Error("InflightReq not set")
	}
}

func TestStep_HavePeerBehindNoWant(t *testing.T) {
	s := NewState(alice)
	var log LogID
	s.OurBest[log] = 200
	_, _ = Step(s, helloFrom(bob))
	out, err := Step(s, Msg{Type: MsgHave, Peer: bob, Log: log, Size: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("expected no outbound, got %+v", out)
	}
}

func TestStep_WantWithNothingToOfferIsSilent(t *testing.T) {
	s := NewState(alice)
	_, _ = Step(s, helloFrom(bob))
	var log LogID
	out, _ := Step(s, Msg{Type: MsgWant, Peer: bob, Log: log, From: 0})
	if len(out) != 0 {
		t.Errorf("expected silent, got %+v", out)
	}
}

func TestStep_WantTriggersSTHWhenAhead(t *testing.T) {
	s := NewState(alice)
	var log LogID
	s.OurBest[log] = 10
	s.OurHashes[log] = [32]byte{0xee}
	_, _ = Step(s, helloFrom(bob))
	out, _ := Step(s, Msg{Type: MsgWant, Peer: bob, Log: log, From: 5})
	if len(out) != 1 || out[0].Type != MsgSTH || out[0].Size != 10 {
		t.Errorf("expected STH{size:10}, got %+v", out)
	}
}

func TestStep_STHTriggersProofReqAndAdvances(t *testing.T) {
	s := NewState(alice)
	var log LogID
	s.OurBest[log] = 5
	_, _ = Step(s, helloFrom(bob))
	out, _ := Step(s, Msg{Type: MsgSTH, Peer: bob, Log: log, Size: 50, Hash: [32]byte{1}})
	if len(out) != 1 || out[0].Type != MsgProofReq {
		t.Fatalf("expected ProofReq, got %+v", out)
	}
	if out[0].OldSize != 5 || out[0].NewSize != 50 {
		t.Errorf("bad proof req bounds: %+v", out[0])
	}
	if s.OurBest[log] != 50 {
		t.Errorf("OurBest not advanced: %d", s.OurBest[log])
	}
}

func TestStep_RejectsSelfMessage(t *testing.T) {
	s := NewState(alice)
	_, err := Step(s, Msg{Type: MsgHello, Peer: alice})
	if err == nil || !strings.Contains(err.Error(), "self") {
		t.Errorf("expected self-message rejection, got %v", err)
	}
}

func TestStep_ProofRespClearsInflight(t *testing.T) {
	s := NewState(alice)
	var log LogID
	_, _ = Step(s, helloFrom(bob))
	s.Peers[bob].InflightReq[log] = 99
	if _, err := Step(s, Msg{Type: MsgProofResp, Peer: bob, Log: log}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Peers[bob].InflightReq[log]; ok {
		t.Error("InflightReq not cleared")
	}
}

func TestStep_UnknownMsgRejected(t *testing.T) {
	s := NewState(alice)
	_, _ = Step(s, helloFrom(bob))
	if _, err := Step(s, Msg{Type: 99, Peer: bob}); err == nil {
		t.Error("expected unknown-type error")
	}
}
