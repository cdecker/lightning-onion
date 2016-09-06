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
		if err != nil {
			log.Fatalf("Error creating message: %v", err)
		}

		binMsg, err := sphinx.SerializeForwardingMessage(msg)
		if err != nil {
			log.Fatalf("Error serializing message: %v", err)
		}

		fmt.Printf("%x\n", binMsg)
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

		privkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), binKey)
		s := sphinx.NewSphinxNode(privkey, &chaincfg.TestNet3Params)

		fm, err := sphinx.ParseForwardingMessage(binMsg)
		if err != nil {
			log.Fatalf("Error parsing message: %v", err)
		}
		p, _, err := s.ProcessForwardingMessage(fm)
		if err != nil {
			log.Fatalf("Failed to decode message: %s", err)
		}

		msg, err := sphinx.SerializeForwardingMessage(p.FwdMsg)
		if err != nil {
			log.Fatalf("Error serializing message: %v", err)
		}
		fmt.Printf("%x\n", msg)
	}
}
