package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	sphinx "github.com/LightningNetwork/lightning-onion"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
)

func main() {
	args := os.Args
	if len(args) == 1 {
		fmt.Printf("Usage: %s (generate|decode) <private-keys>\n", args[0])
	} else if args[1] == "generate" {
		var privKeys []*btcec.PrivateKey
		var route []*btcec.PublicKey
		for i, hexKey := range args[2:] {
			binKey, err := hex.DecodeString(hexKey)
			if err != nil || len(binKey) != 32 {
				log.Fatalf("%s is not a valid hex privkey %s", hexKey, err)
			}
			privkey, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), binKey)
			route = append(route, pubkey)
			privKeys = append(privKeys, privkey)
			fmt.Fprintf(os.Stderr, "Node %d pubkey %x\n", i, pubkey.SerializeCompressed())
		}

		sessionKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), bytes.Repeat([]byte{'A'}, 32))

		var hopPayloads [][]byte
		for i := 0; i < len(route); i++ {
			payload := bytes.Repeat([]byte{'A'}, 20)
			hopPayloads = append(hopPayloads, payload)
		}

		msg, err := sphinx.NewForwardingMessage(route, sessionKey, []byte("testing"), hopPayloads)
		_, _ = msg, err
		fmt.Printf("%x%x%x%x%x\n", msg.Header.EphemeralKey.SerializeCompressed(),
			msg.Header.HeaderMAC, msg.Header.RoutingInfo, msg.Header.HopPayload, msg.Msg)
	} else if args[1] == "decode" {
		binKey, err := hex.DecodeString(args[2])
		if len(binKey) != 32 || err != nil {
			log.Fatalf("Argument not a valid hex private key")
		}
		bytes, _ := ioutil.ReadAll(os.Stdin)
		binMsg, err := hex.DecodeString(strings.TrimSpace(string(bytes)))
		if err != nil {
			log.Fatalf("Error decoding message: %s", err)
		}

		privkey, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), binKey)
		fmt.Fprintf(os.Stderr, "Node pubkey %x\n", pubkey.SerializeCompressed())

		ephemeralKey, _ := btcec.ParsePubKey(binMsg[:33], btcec.S256())

		fm := sphinx.ForwardingMessage{
			Header: &sphinx.MixHeader{
				EphemeralKey: ephemeralKey,
			},
		}

		n := 33

		copy(fm.Msg[:], binMsg[len(binMsg)-1024:len(binMsg)])
		copy(fm.Header.HeaderMAC[:], binMsg[n:n+20])
		n += 20
		copy(fm.Header.RoutingInfo[:], binMsg[n:n+len(fm.Header.RoutingInfo)])
		n += len(fm.Header.RoutingInfo)
		copy(fm.Header.HopPayload[:], binMsg[n:n+len(fm.Header.HopPayload)])
		s := sphinx.NewSphinxNode(privkey, &chaincfg.TestNet3Params)
		p, _, err := s.ProcessForwardingMessage(&fm)
		if err != nil {
			log.Fatalf("Failed to decode message: %s", err)
		}
		msg := p.FwdMsg
		fmt.Printf("%x%x%x%x%x\n", msg.Header.EphemeralKey.SerializeCompressed(),
			msg.Header.HeaderMAC, msg.Header.RoutingInfo, msg.Header.HopPayload, msg.Msg)
	}
}
