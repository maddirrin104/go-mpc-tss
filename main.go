package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	signing "github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// số bên tham gia MPC
const (
	partyCount = 3
	threshold  = 2 // 2-of-3
)

// một party cục bộ: giữ state TSS + 2 channel gửi/nhận
type localParty struct {
	id     *tss.PartyID
	party  tss.Party
	outCh  chan tss.Message
	endKg  chan *keygen.LocalPartySaveData
	endSig chan *common.SignatureData
}

func main() {
	// ======== 1. Chuẩn bị danh sách party ID ========
	parties := make([]*tss.PartyID, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		// id string, moniker, uniqueKey (big.Int)
		uid := big.NewInt(int64(i + 1))
		pid := tss.NewPartyID(fmt.Sprintf("P%d", i+1), "", uid)
		parties = append(parties, pid)
	}
	// sort để toàn bộ node có cùng thứ tự
	parties = tss.SortPartyIDs(parties)
	peerCtx := tss.NewPeerContext(parties)
	curve := tss.S256()

	// ======== 2. Sinh pre-params (Paillier, safe primes, ...) ========
	// nên làm trước vì khá nặng
	preParams, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		log.Fatalf("generate pre-params fail: %v", err)
	}

	// ======== 3. Tạo 3 local parties chạy keygen ========
	var (
		pList    []*localParty
		wgKeygen sync.WaitGroup
	)
	wgKeygen.Add(partyCount)

	// map để định tuyến message
	partyMap := make(map[string]*localParty)

	for idx, pid := range parties {
		// mỗi party có out channel riêng
		outCh := make(chan tss.Message, partyCount)
		endCh := make(chan *keygen.LocalPartySaveData, 1)

		params := tss.NewParameters(curve, peerCtx, pid, partyCount, threshold)

		lp := keygen.NewLocalParty(params, outCh, endCh, *preParams)

		lpWrap := &localParty{
			id:    pid,
			party: lp,
			outCh: outCh,
			endKg: endCh,
		}
		pList = append(pList, lpWrap)
		partyMap[pid.Id] = lpWrap

		go func(p tss.Party, who string) {
			defer wgKeygen.Done()
			if err := p.Start(); err != nil {
				log.Printf("[%s] keygen start err: %v", who, err)
			}
		}(lp, pid.Id)

		// mỗi party có goroutine đọc outCh và forward sang các party khác
		go func(from *localParty) {
			for msg := range from.outCh {
				routeMessage(msg, from.id, partyMap)
			}
		}(lpWrap)

		_ = idx
	}

	// ======== 4. Thu kết quả keygen ========
	keygenDone := 0
	keyDataByID := make(map[string]*keygen.LocalPartySaveData)

	for keygenDone < partyCount {
		for _, p := range pList {
			select {
			case data := <-p.endKg:
				keygenDone++
				keyDataByID[p.id.Id] = data
				log.Printf("[%s] keygen DONE", p.id.Id)
			default:
				// nothing
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	wgKeygen.Wait()

	// ta có public key chung (giống nhau ở mọi node)
	pub := keyDataByID[pList[0].id.Id].ECDSAPub
	log.Printf("==> Public key (X,Y):\nX = %s\nY = %s", pub.X().String(), pub.Y().String())
	// bạn có thể chuyển pub này sang địa chỉ Ethereum, rồi nhét vào HTLC

	// ======== 5. Bây giờ ký ngưỡng với 2/3 node ========
	msg := sha256.Sum256([]byte("mpc-sign-for-mp-htlc-lgp"))
	m := msg[:]
	log.Printf("message hash = %s", hex.EncodeToString(m))

	// chọn 2 node đầu để ký
	signers := []*localParty{pList[0], pList[1]}

	// chuẩn bị channels cho signing
	var wgSign sync.WaitGroup
	wgSign.Add(len(signers))

	// ta cần peer context chỉ cho 2 signer này
	signerIDs := []*tss.PartyID{signers[0].id, signers[1].id}
	signerIDs = tss.SortPartyIDs(signerIDs)
	signerCtx := tss.NewPeerContext(signerIDs)

	// map riêng cho phase ký
	signerMap := make(map[string]*localParty)

	for _, sp := range signers {
		outCh := make(chan tss.Message, len(signers))
		endCh := make(chan *common.SignatureData, 1)

		params := tss.NewParameters(curve, signerCtx, sp.id, len(signers), threshold)

		// lấy key share từ bước keygen
		keyData := keyDataByID[sp.id.Id]

		sParty := signing.NewLocalParty(new(big.Int).SetBytes(m), params, *keyData, outCh, endCh)

		sp.outCh = outCh
		sp.endSig = endCh
		sp.party = sParty
		signerMap[sp.id.Id] = sp

		go func(p tss.Party, who string) {
			defer wgSign.Done()
			if err := p.Start(); err != nil {
				log.Printf("[%s] signing start err: %v", who, err)
			}
		}(sParty, sp.id.Id)

		go func(from *localParty) {
			for msg := range from.outCh {
				routeMessage(msg, from.id, signerMap)
			}
		}(sp)
	}

	// chờ chữ ký
	sigCollected := 0
	var finalSig *common.SignatureData
	for sigCollected < len(signers) {
		for _, sp := range signers {
			select {
			case sig := <-sp.endSig:
				sigCollected++
				// tất cả nhận cùng 1 sig, nên lấy cái đầu
				if finalSig == nil {
					finalSig = sig
				}
				log.Printf("[%s] signing DONE", sp.id.Id)
			default:
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	wgSign.Wait()

	if finalSig == nil {
		log.Fatalf("signing failed, no signature collected")
	}

	// in chữ ký
	r := finalSig.R
	s := finalSig.S
	log.Printf("==> Threshold signature:")
	log.Printf("r = %s", hex.EncodeToString(r))
	log.Printf("s = %s", hex.EncodeToString(s))
	log.Printf("recid = %d (dùng để dựng chữ ký kiểu Ethereum)", finalSig.SignatureRecovery)

	fmt.Println("DONE.")
}

// routeMessage chuyển 1 message TSS từ 'from' sang các party còn lại
func routeMessage(msg tss.Message, from *tss.PartyID, partyMap map[string]*localParty) {
	wireBytes, routing, err := msg.WireBytes()
	if err != nil {
		log.Printf("wirebytes err: %v", err)
		return
	}

	if routing.IsBroadcast {
		for id, p := range partyMap {
			if id == from.Id {
				continue
			}
			if ok, err2 := p.party.UpdateFromBytes(wireBytes, from, true); !ok || err2 != nil {
				log.Printf("broadcast to %s failed: %v", id, err2)
			}
		}
		return
	}

	// point-to-point
	for _, to := range routing.To {
		dst, ok := partyMap[to.Id]
		if !ok {
			log.Printf("no party %s in map", to.Id)
			continue
		}
		if ok2, err2 := dst.party.UpdateFromBytes(wireBytes, from, false); !ok2 || err2 != nil {
			log.Printf("unicast to %s failed: %v", to.Id, err2)
		}
	}
}
