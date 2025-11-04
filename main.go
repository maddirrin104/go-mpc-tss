package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	signing "github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// ===== cấu hình demo =====
const (
	partyCount = 3
	// 2-of-3  => t = 1
	threshold = 1
)

// gom trong 1 struct để dễ quản lý
type kgNode struct {
	id    *tss.PartyID
	party tss.Party
	out   chan tss.Message
	done  chan *keygen.LocalPartySaveData
}

type signNode struct {
	id    *tss.PartyID
	party tss.Party
	out   chan tss.Message
	done  chan *common.SignatureData
}

func main() {
	// 1. tạo danh sách ID
	parties := make([]*tss.PartyID, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		key := big.NewInt(int64(i + 1))
		p := tss.NewPartyID(fmt.Sprintf("P%d", i+1), "", key)
		parties = append(parties, p)
	}
	parties = tss.SortPartyIDs(parties)
	peerCtx := tss.NewPeerContext(parties)
	curve := tss.S256()

	// 2. pre-params (nặng, nên tái sử dụng)
	preParams, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		log.Fatalf("generate preparams: %v", err)
	}

	// 3. chạy keygen cho 3 node trong memory
	kgNodes := make([]*kgNode, 0, partyCount)
	nodeMap := make(map[string]*kgNode, partyCount)

	for _, pid := range parties {
		outCh := make(chan tss.Message, partyCount)
		endCh := make(chan *keygen.LocalPartySaveData, 1)

		params := tss.NewParameters(curve, peerCtx, pid, partyCount, threshold)

		// chú ý: NewLocalParty(..., preParams) nhận giá trị, không phải pointer
		p := keygen.NewLocalParty(params, outCh, endCh, *preParams)

		n := &kgNode{
			id:    pid,
			party: p,
			out:   outCh,
			done:  endCh,
		}
		kgNodes = append(kgNodes, n)
		nodeMap[pid.Id] = n
	}

	// forward message cho pha keygen
	for _, n := range kgNodes {
		go func(me *kgNode) {
			for msg := range me.out {
				routeKG(msg, me.id, nodeMap)
			}
		}(n)
	}

	// start từng party
	for _, n := range kgNodes {
		if err := n.party.Start(); err != nil {
			log.Fatalf("[%s] start keygen: %v", n.id.Id, err)
		}
	}

	// chờ thu 3 kết quả
	keyDataByID := make(map[string]*keygen.LocalPartySaveData, partyCount)
	doneCount := 0
	for doneCount < partyCount {
		for _, n := range kgNodes {
			select {
			case data := <-n.done:
				keyDataByID[n.id.Id] = data
				doneCount++
				log.Printf("[%s] KEYGEN DONE", n.id.Id)
			default:
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	// public key chung
	pub := keyDataByID[kgNodes[0].id.Id].ECDSAPub
	log.Printf("==> pubkey X=%s\nY=%s", pub.X().String(), pub.Y().String())

	// 4. SIGN 2-of-3
	msg := sha256.Sum256([]byte("mpc-sign-for-mp-htlc-lgp"))
	m := new(big.Int).SetBytes(msg[:])

	// chọn 2 signer đầu
	signerParties := []*tss.PartyID{kgNodes[0].id, kgNodes[1].id}
	signerParties = tss.SortPartyIDs(signerParties)
	signerCtx := tss.NewPeerContext(signerParties)

	// tạo map để định tuyến riêng cho pha ký
	signMap := make(map[string]*signNode, len(signerParties))
	signNodes := make([]*signNode, 0, len(signerParties))

	for _, kgN := range kgNodes[:2] {
		outCh := make(chan tss.Message, len(signerParties))
		endCh := make(chan *common.SignatureData, 1)

		params := tss.NewParameters(curve, signerCtx, kgN.id, len(signerParties), threshold)

		sParty := signing.NewLocalParty(m, params, *keyDataByID[kgN.id.Id], outCh, endCh)

		sn := &signNode{
			id:    kgN.id,
			party: sParty,
			out:   outCh,
			done:  endCh,
		}
		signNodes = append(signNodes, sn)
		signMap[kgN.id.Id] = sn
	}

	// forward cho pha ký
	for _, n := range signNodes {
		go func(me *signNode) {
			for msg := range me.out {
				routeSign(msg, me.id, signMap)
			}
		}(n)
	}

	// start ký
	for _, n := range signNodes {
		if err := n.party.Start(); err != nil {
			log.Fatalf("[%s] start sign: %v", n.id.Id, err)
		}
	}

	// thu chữ ký
	var finalSig *common.SignatureData
	doneSig := 0
	for doneSig < len(signNodes) {
		for _, n := range signNodes {
			select {
			case sig := <-n.done:
				doneSig++
				if finalSig == nil {
					finalSig = sig
				}
				log.Printf("[%s] SIGN DONE", n.id.Id)
			default:
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	if finalSig == nil {
		log.Fatal("signing failed, no signature")
	}

	// in chữ ký
	fmt.Printf("==> TSS signature:\n")
	fmt.Printf("r = %s\n", hex.EncodeToString(finalSig.R))
	fmt.Printf("s = %s\n", hex.EncodeToString(finalSig.S))
	fmt.Printf("v(recid) = %d\n", finalSig.SignatureRecovery)

	// 5. verify lại bằng ecdsa chuẩn
	ok := verifyECDSA(pub, msg[:], finalSig.R, finalSig.S)
	fmt.Printf("ECDSA verify = %v\n", ok)

	// 6. nếu cần chữ ký kiểu Ethereum 65 byte để gửi sang chain:
	ethSig := makeEthSignature(finalSig.R, finalSig.S, finalSig.SignatureRecovery)
	fmt.Printf("ethSig(65) = 0x%s\n", hex.EncodeToString(ethSig))

	fmt.Println("DONE.")
}

// === routing cho keygen ===
func routeKG(msg tss.Message, from *tss.PartyID, nodes map[string]*kgNode) {
	wire, routing, err := msg.WireBytes()
	if err != nil {
		log.Printf("KG wire err: %v", err)
		return
	}
	if routing.IsBroadcast {
		for id, n := range nodes {
			if id == from.Id {
				continue
			}
			if ok, err2 := n.party.UpdateFromBytes(wire, from, true); !ok || err2 != nil {
				log.Printf("KG broadcast -> %s fail: %v", id, err2)
			}
		}
		return
	}
	for _, to := range routing.To {
		dst := nodes[to.Id]
		if ok, err2 := dst.party.UpdateFromBytes(wire, from, false); !ok || err2 != nil {
			log.Printf("KG unicast -> %s fail: %v", to.Id, err2)
		}
	}
}

// === routing cho signing ===
func routeSign(msg tss.Message, from *tss.PartyID, nodes map[string]*signNode) {
	wire, routing, err := msg.WireBytes()
	if err != nil {
		log.Printf("SIGN wire err: %v", err)
		return
	}
	if routing.IsBroadcast {
		for id, n := range nodes {
			if id == from.Id {
				continue
			}
			if ok, err2 := n.party.UpdateFromBytes(wire, from, true); !ok || err2 != nil {
				log.Printf("SIGN broadcast -> %s fail: %v", id, err2)
			}
		}
		return
	}
	for _, to := range routing.To {
		dst := nodes[to.Id]
		if ok, err2 := dst.party.UpdateFromBytes(wire, from, false); !ok || err2 != nil {
			log.Printf("SIGN unicast -> %s fail: %v", to.Id, err2)
		}
	}
}

// verify ECDSA chuẩn
func verifyECDSA(pub interface {
	X() *big.Int
	Y() *big.Int
}, msg []byte, rBz, sBz []byte) bool {
	x := pub.X()
	y := pub.Y()
	r := new(big.Int).SetBytes(rBz)
	s := new(big.Int).SetBytes(sBz)
	ecdsaPub := ecdsa.PublicKey{
		Curve: elliptic.P256(), // tss.S256() cũng là secp256k1 → nếu bạn build bằng go-ethereum thì dùng btcec
		X:     x,
		Y:     y,
	}
	return ecdsa.Verify(&ecdsaPub, msg, r, s)
}

func makeEthSignature(rBz, sBz []byte, recid []byte) []byte {
	var v byte
	if len(recid) > 0 {
		v = recid[0]
	} else {
		v = 0
	}
	sig := make([]byte, 65)
	copy(sig[0:32], rBz)
	copy(sig[32:64], sBz)
	sig[64] = v
	return sig
}
