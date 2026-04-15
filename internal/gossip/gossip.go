// Package gossip implements the witness gossip-protocol state
// machine. It is intentionally pure: no sockets, no goroutines, no
// timers. The transport (HTTP, libp2p, NATS) drives the machine by
// delivering inbound messages via Step and emitting whatever the
// machine returns. This keeps every state transition exhaustively
// testable and lets us swap transports without rewriting protocol
// logic.
//
// Protocol sketch (mirrors the IETF Trillian witness draft and the
// Sigsum cosignature gossip):
//
//	Hello{peerID, supportedAlgs}      // handshake
//	Have{logID, treeSize, rootHash}   // I have this STH
//	Want{logID, fromSize}             // please send STH+proof for ≥fromSize
//	STH{logID, size, hash, sig}       // signed tree head
//	ProofReq{logID, oldSize, newSize} // need consistency proof
//	ProofResp{logID, oldSize, newSize, hashes}
package gossip

import (
	"errors"
	"fmt"
)

type MsgType uint8

const (
	MsgHello MsgType = iota + 1
	MsgHave
	MsgWant
	MsgSTH
	MsgProofReq
	MsgProofResp
)

type LogID [32]byte

type Msg struct {
	Type MsgType
	Peer string

	// Hello
	Algs []string

	// Have / Want / STH / Proof*
	Log     LogID
	Size    uint64
	From    uint64
	OldSize uint64
	NewSize uint64
	Hash    [32]byte
	Sig     []byte
	Proof   [][32]byte
}

// PeerInfo captures what we know about a remote peer.
type PeerInfo struct {
	HelloSeen   bool
	Algs        []string
	BestSTH     map[LogID]uint64 // largest size we've heard
	InflightReq map[LogID]uint64 // newSize requested but not yet answered
}

// State is the machine's full visible state. Callers are expected
// to keep one State per local witness instance.
type State struct {
	Self      string
	Peers     map[string]*PeerInfo
	OurBest   map[LogID]uint64
	OurHashes map[LogID][32]byte
}

func NewState(self string) *State {
	return &State{
		Self:      self,
		Peers:     map[string]*PeerInfo{},
		OurBest:   map[LogID]uint64{},
		OurHashes: map[LogID][32]byte{},
	}
}

// Step folds one inbound message into State and returns the
// outbound messages the transport should send. A returned error is
// a protocol violation (drop the peer); state is left unchanged on
// error.
func Step(s *State, in Msg) ([]Msg, error) {
	if s == nil {
		return nil, errors.New("gossip: nil state")
	}
	if in.Peer == "" {
		return nil, errors.New("gossip: missing peer")
	}
	if in.Peer == s.Self {
		return nil, errors.New("gossip: self-message")
	}
	p := s.Peers[in.Peer]
	if p == nil {
		p = &PeerInfo{
			BestSTH:     map[LogID]uint64{},
			InflightReq: map[LogID]uint64{},
		}
		s.Peers[in.Peer] = p
	}
	// Hello must be first.
	if !p.HelloSeen && in.Type != MsgHello {
		return nil, fmt.Errorf("gossip: peer %q sent %d before Hello", in.Peer, in.Type)
	}

	switch in.Type {
	case MsgHello:
		if p.HelloSeen {
			return nil, errors.New("gossip: duplicate Hello")
		}
		p.HelloSeen = true
		p.Algs = append([]string(nil), in.Algs...)
		// Reply with Hello and one Have per known log.
		out := []Msg{{Type: MsgHello, Peer: s.Self, Algs: defaultAlgs()}}
		for log, size := range s.OurBest {
			out = append(out, Msg{
				Type: MsgHave, Peer: s.Self,
				Log: log, Size: size, Hash: s.OurHashes[log],
			})
		}
		return out, nil

	case MsgHave:
		if in.Size > p.BestSTH[in.Log] {
			p.BestSTH[in.Log] = in.Size
		}
		// If peer is ahead of us, request the gap.
		if in.Size > s.OurBest[in.Log] {
			p.InflightReq[in.Log] = in.Size
			return []Msg{{
				Type: MsgWant, Peer: s.Self,
				Log: in.Log, From: s.OurBest[in.Log],
			}}, nil
		}
		return nil, nil

	case MsgWant:
		if s.OurBest[in.Log] <= in.From {
			return nil, nil // nothing to offer
		}
		return []Msg{{
			Type: MsgSTH, Peer: s.Self,
			Log: in.Log, Size: s.OurBest[in.Log], Hash: s.OurHashes[in.Log],
		}}, nil

	case MsgSTH:
		if in.Size > s.OurBest[in.Log] {
			// Demand a consistency proof before we adopt it.
			old := s.OurBest[in.Log]
			s.OurBest[in.Log] = in.Size
			s.OurHashes[in.Log] = in.Hash
			delete(p.InflightReq, in.Log)
			return []Msg{{
				Type: MsgProofReq, Peer: s.Self,
				Log: in.Log, OldSize: old, NewSize: in.Size,
			}}, nil
		}
		return nil, nil

	case MsgProofReq:
		// Offline-only state machine: callers wire the actual proof
		// generator. Here we just acknowledge the request shape.
		return []Msg{{
			Type: MsgProofResp, Peer: s.Self,
			Log: in.Log, OldSize: in.OldSize, NewSize: in.NewSize,
		}}, nil

	case MsgProofResp:
		// Verification is the caller's responsibility (uses the
		// inclusion package). Machine just clears any in-flight req.
		delete(p.InflightReq, in.Log)
		return nil, nil

	default:
		return nil, fmt.Errorf("gossip: unknown msg type %d", in.Type)
	}
}

func defaultAlgs() []string { return []string{"ed25519", "hybrid-ed25519-mldsa65"} }
