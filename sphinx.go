package sphinx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

const (
	// So, 256-bit EC curve pubkeys, 160-bit keys symmetric encryption,
	// 160-bit keys for HMAC, etc. Represented in bytes.
	securityParameter = 20

	// Default message size in bytes. This is probably *much* too big atm?
	messageSize = 1024

	// How much extra information we want to store in the onion
	// routing header. The paper used this to store an HMAC of the
	// payload, but we'll put it somewhere else.
	extraInfo = 0

	// The maximum path length. This should be set to an
	// estiamate of the upper limit of the diameter of the node graph.
	numMaxHops = 5

	// The number of bytes produced by our CSPRG for the key stream
	// implementing our stream cipher to encrypt/decrypt the mix header. The
	// last 2 * securityParameter bytes are only used in order to generate/check
	// the MAC over the header.
	numStreamBytes = (2*numMaxHops+2)*securityParameter + extraInfo

	// Size in bytes of the shared secrets.
	sharedSecretSize = 32

	// Per-hop payload size
	hopPayloadSize = 20

	// Fixed size of the the routing info. This consists of a 20
	// byte address and a 20 byte HMAC for each hop of the route,
	// the first pair in cleartext and the following pairs
	// increasingly obfuscated. In case fewer than numMaxHops are
	// used, then the remainder is padded with null-bytes, also
	// obfuscated.
	routingInfoSize = 2*numMaxHops*securityParameter + extraInfo
)

// MixHeader is the onion wrapped hop-to-hop routing information neccessary to
// propagate a message through the mix-net without intermediate nodes having
// knowledge of their position within the route, the source, the destination,
// and finally the identities of the past/future nodes in the route. At each hop
// the ephemeral key is used by the node to perform ECDH between itself and the
// source node. This derived secret key is used to check the MAC of the entire mix
// header, decrypt the next set of routing information, and re-randomize the
// ephemeral key for the next node in the path. This per-hop re-randomization
// allows us to only propgate a single group element through the onion route.
// TODO(roasbeef): serialize/deserialize methods..
type MixHeader struct {
	EphemeralKey *btcec.PublicKey
	RoutingInfo  [routingInfoSize]byte
	HeaderMAC    [securityParameter]byte
	HopPayload   [numMaxHops * hopPayloadSize]byte
}

// NewMixHeader creates a new mix header which is capable of
// obliviously routing a message through the mix-net path outline by
// 'paymentPath'.  This function returns the created mix header along
// with a derived shared secret for each node in the path.
func NewMixHeader(paymentPath []*btcec.PublicKey, sessionKey *btcec.PrivateKey,
	message [1024]byte, rawHopPayloads [][]byte) (*MixHeader,
	[1024]byte, [][sharedSecretSize]byte, error) {

	// Each hop performs ECDH with our ephemeral key pair to arrive at a
	// shared secret. Additionally, each hop randomizes the group element
	// for the next hop by multiplying it by the blinding factor. This way
	// we only need to transmit a single group element, and hops can't link
	// a session back to us if they have several nodes in the path.
	numHops := len(paymentPath)
	hopEphemeralPubKeys := make([]*btcec.PublicKey, numHops)
	hopSharedSecrets := make([][sha256.Size]byte, numHops)
	hopBlindingFactors := make([][sha256.Size]byte, numHops)

	// Compute the triplet for the first hop outside of the main loop.
	// Within the loop each new triplet will be computed recursively based
	// off of the blinding factor of the last hop.
	hopEphemeralPubKeys[0] = sessionKey.PubKey()
	hopSharedSecrets[0] = sha256.Sum256(btcec.GenerateSharedSecret(sessionKey, paymentPath[0]))
	hopBlindingFactors[0] = computeBlindingFactor(hopEphemeralPubKeys[0], hopSharedSecrets[0][:])

	// Now recursively compute the ephemeral ECDH pub keys, the shared
	// secret, and blinding factor for each hop.
	for i := 1; i <= numHops-1; i++ {
		// a_{n} = a_{n-1} x c_{n-1} -> (Y_prev_pub_key x prevBlindingFactor)
		hopEphemeralPubKeys[i] = blindGroupElement(hopEphemeralPubKeys[i-1],
			hopBlindingFactors[i-1][:])

		// s_{n} = sha256( y_{n} x c_{n-1} ) ->
		// (Y_their_pub_key x x_our_priv) x all prev blinding factors
		yToX := blindGroupElement(paymentPath[i], sessionKey.D.Bytes())
		hopSharedSecrets[i] = sha256.Sum256(multiScalarMult(yToX, hopBlindingFactors[:i]).X.Bytes())

		// TODO(roasbeef): prob don't need to store all blinding factors, only the prev...
		// b_{n} = sha256(a_{n} || s_{n})
		hopBlindingFactors[i] = computeBlindingFactor(hopEphemeralPubKeys[i],
			hopSharedSecrets[i][:])

	}

	// Generate the padding, called "filler strings" in the paper.
	filler := generateHeaderPadding("rho", numHops, 2*securityParameter, hopSharedSecrets)
	hopFiller := generateHeaderPadding("gamma", numHops, hopPayloadSize, hopSharedSecrets)

	// First we generate the routing info + MAC for the very last hop.
	mixHeader := bytes.Repeat([]byte{0x00}, (2*(numMaxHops-numHops)+2)*securityParameter+extraInfo)

	var hopPayloads [numMaxHops * hopPayloadSize]byte

	hopStreamBytes := generateCipherStream(generateKey("gamma", hopSharedSecrets[numHops-1]), numMaxHops*hopPayloadSize)

	// Manually insert the first hopPayload, otherwise
	copy(hopPayloads[:], rawHopPayloads[numHops-1])
	xor(hopPayloads[:], hopPayloads[:], hopStreamBytes)
	copy(hopPayloads[len(hopPayloads)-len(hopFiller):], hopFiller)

	// Encrypt the header for the final hop with the shared secret the
	// destination will eventually derive, then pad the message out to full
	// size with the "random" filler bytes.
	streamBytes := generateCipherStream(generateKey("rho", hopSharedSecrets[numHops-1]), numStreamBytes)
	xor(mixHeader, mixHeader, streamBytes[:routingInfoSize])
	mixHeader = append(mixHeader, filler...)

	onion := lionessEncode(generateKey("pi", hopSharedSecrets[numHops-1]), message)
	// Calculate a MAC over the encrypted mix header for the last hop
	// (including the filler bytes), using the same shared secret key as
	// used for encryption above.
	headerMac := calcMac(generateKey("mu", hopSharedSecrets[numHops-1]), append(append(mixHeader, hopPayloads[:]...), onion[:]...))

	// Now we compute the routing information for each hop, along with a
	// MAC of the routing info using the shared key for that hop.
	for i := numHops - 2; i >= 0; i-- {
		// The next hop from the point of view of the current hop. Node
		// ID's are currently the hash160 of a node's pubKey serialized
		// in compressed format.
		nodeID := btcutil.Hash160(paymentPath[i+1].SerializeCompressed())

		var b bytes.Buffer
		b.Write(nodeID)
		// MAC for mix header.
		b.Write(headerMac[:])
		// Mix header itself.
		b.Write(mixHeader[:(2*numMaxHops-2)*securityParameter+extraInfo])
		streamBytes := generateCipherStream(generateKey("rho", hopSharedSecrets[i]), numStreamBytes)
		onion = lionessEncode(generateKey("pi", hopSharedSecrets[i]), onion)
		xor(mixHeader, b.Bytes(), streamBytes[:routingInfoSize])

		// Obfuscate the per-hop payload
		var b2 bytes.Buffer
		b2.Write(rawHopPayloads[i][:20])
		b2.Write(bytes.Repeat([]byte{0x00}, hopPayloadSize-len(rawHopPayloads[i])))
		b2.Write(hopPayloads[:])
		hopStreamBytes := generateCipherStream(generateKey("gamma", hopSharedSecrets[i]), uint(len(hopPayloads)))
		xor(hopPayloads[:], b2.Bytes(), hopStreamBytes)

		packet := append(append(mixHeader, hopPayloads[:]...), onion[:]...)
		headerMac = calcMac(generateKey("mu", hopSharedSecrets[i]), packet)
	}

	var r [routingInfoSize]byte
	copy(r[:], mixHeader)
	header := &MixHeader{
		EphemeralKey: hopEphemeralPubKeys[0],
		RoutingInfo:  r,
		HeaderMAC:    headerMac,
		HopPayload:   hopPayloads,
	}
	return header, onion, hopSharedSecrets, nil
}

// generateHeaderPadding derives the bytes for padding the mix header to ensure
// it remains fixed sized throughout route transit. At each step, we add
// 2*securityParameter padding of zeroes, concatenate it to the previous
// filler, then decrypt it (XOR) with the secret key of the current hop. When
// encrypting the mix header we essentially do the reverse of this operation:
// we "encrypt" the padding, and drop 2*k number of zeroes. As nodes process
// the mix header they add the padding (2*k) in order to check the MAC and
// decrypt the next routing information eventually leaving only the original
// "filler" bytes produced by this function at the last hop. Using this
// methodology, the size of the mix header stays constant at each hop.
func generateHeaderPadding(key string, numHops int, hopSize int, sharedSecrets [][sharedSecretSize]byte) []byte {
	filler := make([]byte, (numHops-1)*hopSize)

	for i := 1; i < numHops; i++ {
		totalFillerSize := ((numMaxHops-i)+1)*hopSize + extraInfo
		streamBytes := generateCipherStream(generateKey(key, sharedSecrets[i-1]),
			numStreamBytes)
		xor(filler, filler, streamBytes[totalFillerSize:totalFillerSize+i*hopSize])
	}
	return filler
}

// ForwardingMessage represents a forwarding message containing onion wrapped
// hop-to-hop routing information along with an onion encrypted payload message
// addressed to the final destination.
// TODO(roasbeef): serialize/deserialize methods..
type ForwardingMessage struct {
	Header *MixHeader
	Msg    [messageSize]byte
}

// NewForwardingMessage generates the a mix header containing the neccessary
// onion routing information required to propagate the message through the
// mixnet, eventually reaching the final node specified by 'identifier'. The
// onion encrypted message payload is then to be delivered to the specified 'dest'
// address.
func NewForwardingMessage(route []*btcec.PublicKey, sessionKey *btcec.PrivateKey,
	message []byte, hopPayloads [][]byte) (*ForwardingMessage, error) {

	// Now for the body of the message.
	var body [1024]byte
	n := copy(body[:], message)
	n += copy(body[n:], []byte{0x7f})
	n += copy(body[n:], bytes.Repeat([]byte{0xff}, messageSize-n))

	// Compute the mix header, and shared secerts for each hop. We pass in
	// the null destination and zero identifier in order for the final node
	// in the route to be able to distinguish the payload as addressed to
	// itself.
	mixHeader, body, _, err := NewMixHeader(route, sessionKey, body, hopPayloads)
	if err != nil {
		return nil, err
	}

	return &ForwardingMessage{Header: mixHeader, Msg: body}, nil
}

// calcMac calculates HMAC-SHA-256 over the message using the passed secret key as
// input to the HMAC.
func calcMac(key [securityParameter]byte, msg []byte) [securityParameter]byte {
	hmac := hmac.New(sha256.New, key[:])
	hmac.Write(msg)
	h := hmac.Sum(nil)

	var mac [securityParameter]byte
	copy(mac[:], h[:securityParameter])

	return mac
}

// xor computes the byte wise XOR of a and b, storing the result in dst.
func xor(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// generateKey...
// used to key rand padding generation, mac, and lionness
// TODO(roasbeef): comment...
func generateKey(keyType string, sharedKey [sharedSecretSize]byte) [securityParameter]byte {
	mac := hmac.New(sha256.New, []byte(keyType))
	mac.Write(sharedKey[:])
	h := mac.Sum(nil)

	var key [securityParameter]byte
	copy(key[:], h[:securityParameter])

	return key
}

// generateHeaderPadding...
// TODO(roasbeef): comments...
func generateCipherStream(key [securityParameter]byte, numBytes uint) []byte {
	// Key must be 16, 24, or 32 bytes.
	block, _ := aes.NewCipher(key[:16])

	// We use AES in CTR mode to generate a psuedo randmom stream of bytes
	// by encrypting a plaintext of all zeroes.
	cipherStream := make([]byte, numBytes)
	plainText := bytes.Repeat([]byte{0}, int(numBytes))

	// Our IV is just zero....
	iv := bytes.Repeat([]byte{0}, aes.BlockSize)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherStream, plainText)

	return cipherStream
}

// ComputeBlindingFactor for the next hop given the ephemeral pubKey and
// sharedSecret for this hop. The blinding factor is computed as the
// sha-256(pubkey || sharedSecret).
func computeBlindingFactor(hopPubKey *btcec.PublicKey, hopSharedSecret []byte) [sha256.Size]byte {
	sha := sha256.New()
	sha.Write(hopPubKey.SerializeCompressed())
	sha.Write(hopSharedSecret)

	var hash [sha256.Size]byte
	copy(hash[:], sha.Sum(nil))
	return hash
}

// blindGroupElement blinds the group element by performing scalar
// multiplication of the group element by blindingFactor: G x blindingFactor.
func blindGroupElement(hopPubKey *btcec.PublicKey, blindingFactor []byte) *btcec.PublicKey {
	newX, newY := hopPubKey.Curve.ScalarMult(hopPubKey.X, hopPubKey.Y, blindingFactor[:])
	return &btcec.PublicKey{hopPubKey.Curve, newX, newY}
}

// multiScalarMult...
func multiScalarMult(hopPubKey *btcec.PublicKey, blindingFactors [][sha256.Size]byte) *btcec.PublicKey {
	finalPubKey := hopPubKey

	for _, blindingFactor := range blindingFactors {
		finalPubKey = blindGroupElement(finalPubKey, blindingFactor[:])
	}

	return finalPubKey
}

type ProcessCode int

const (
	ExitNode = iota
	MoreHops
	Failure
)

// processMsgAction....
type ProcessMsgAction struct {
	Action ProcessCode

	NextHop [securityParameter]byte
	FwdMsg  *ForwardingMessage
}

// SphinxNode...
type SphinxNode struct {
	nodeID [securityParameter]byte
	// TODO(roasbeef): swap out with btcutil.AddressLightningKey maybe?
	nodeAddr *btcutil.AddressPubKeyHash
	lnKey    *btcec.PrivateKey

	seenSecrets map[[sharedSecretSize]byte]struct{}
}

// NewSphinxNode...
func NewSphinxNode(nodeKey *btcec.PrivateKey, net *chaincfg.Params) *SphinxNode {
	var nodeID [securityParameter]byte
	copy(nodeID[:], btcutil.Hash160(nodeKey.PubKey().SerializeCompressed()))

	// Safe to ignore the error here, nodeID is 20 bytes.
	nodeAddr, _ := btcutil.NewAddressPubKeyHash(nodeID[:], net)

	return &SphinxNode{
		nodeID:   nodeID,
		nodeAddr: nodeAddr,
		lnKey:    nodeKey,
		// TODO(roasbeef): replace instead with bloom filter?
		// * https://moderncrypto.org/mail-archive/messaging/2015/001911.html
		seenSecrets: make(map[[sharedSecretSize]byte]struct{}),
	}
}

// ProcessMixHeader...
// TODO(roasbeef): proto msg enum?
func (s *SphinxNode) ProcessForwardingMessage(fwdMsg *ForwardingMessage) (*ProcessMsgAction, error) {
	mixHeader := fwdMsg.Header
	onionMsg := fwdMsg.Msg

	dhKey := mixHeader.EphemeralKey
	routeInfo := mixHeader.RoutingInfo
	headerMac := mixHeader.HeaderMAC

	// Ensure that the public key is on our curve.
	if !s.lnKey.Curve.IsOnCurve(dhKey.X, dhKey.Y) {
		return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
	}

	// Compute our shared secret.
	sharedSecret := sha256.Sum256(btcec.GenerateSharedSecret(s.lnKey, dhKey))

	// In order to mitigate replay attacks, if we've seen this particular
	// shared secret before, cease processing and just drop this forwarding
	// message.
	if _, ok := s.seenSecrets[sharedSecret]; ok {
		return nil, fmt.Errorf("shared secret previously seen")
	}

	// Using the derived shared secret, ensure the integrity of the routing
	// information by checking the attached MAC without leaking timing
	// information.

	message := append(append(routeInfo[:], mixHeader.HopPayload[:]...), onionMsg[:]...)
	calculatedMac := calcMac(generateKey("mu", sharedSecret), message)
	if !hmac.Equal(headerMac[:], calculatedMac[:]) {
		return nil, fmt.Errorf("MAC mismatch %x != %x, rejecting forwarding message", headerMac, calculatedMac)
	}

	// The MAC checks out, mark this current shared secret as processed in
	// order to mitigate future replay attacks.
	s.seenSecrets[sharedSecret] = struct{}{}

	// Attach the padding zeroes in order to properly strip an encryption
	// layer off the routing info revealing the routing information for the
	// next hop.
	var hopInfo [numStreamBytes]byte
	streamBytes := generateCipherStream(generateKey("rho", sharedSecret), numStreamBytes)
	headerWithPadding := append(routeInfo[:], bytes.Repeat([]byte{0}, 2*securityParameter)...)
	xor(hopInfo[:], headerWithPadding, streamBytes)

	// Randomize the DH group element for the next hop using the
	// deterministic blinding factor.
	blindingFactor := computeBlindingFactor(dhKey, sharedSecret[:])
	nextDHKey := blindGroupElement(dhKey, blindingFactor[:])

	// Parse out the ID of the next node in the route.
	var nextHop [securityParameter]byte
	copy(nextHop[:], hopInfo[:securityParameter])

	// MAC and MixHeader for the next hop.
	var nextMac [securityParameter]byte
	copy(nextMac[:], hopInfo[securityParameter:securityParameter*2])
	var nextMixHeader [routingInfoSize]byte
	copy(nextMixHeader[:], hopInfo[securityParameter*2:])

	hopPayloadsWithPadding := append(mixHeader.HopPayload[:], bytes.Repeat([]byte{0x00}, hopPayloadSize)...)
	hopStreamBytes := generateCipherStream(generateKey("gamma", sharedSecret), uint(len(hopPayloadsWithPadding)))
	xor(hopPayloadsWithPadding, hopPayloadsWithPadding, hopStreamBytes)

	myPayload := hopPayloadsWithPadding[:hopPayloadSize]
	fmt.Printf("My Payload %x\n", myPayload)
	var nextHopPayloads [numMaxHops * hopPayloadSize]byte
	copy(nextHopPayloads[:], hopPayloadsWithPadding[hopPayloadSize:])

	// Strip a single layer of encryption from the onion for the
	// next hop to also process.
	nextOnion := lionessDecode(generateKey("pi", sharedSecret), onionMsg)

	nextFwdMsg := &ForwardingMessage{
		Header: &MixHeader{
			EphemeralKey: nextDHKey,
			RoutingInfo:  nextMixHeader,
			HeaderMAC:    nextMac,
			HopPayload:   nextHopPayloads,
		},
		Msg: nextOnion,
	}

	var action ProcessCode = MoreHops

	if bytes.Compare(bytes.Repeat([]byte{0x00}, 20), nextMac[:]) == 0 {
		action = ExitNode
	}

	return &ProcessMsgAction{
		Action:  action,
		NextHop: nextHop,
		FwdMsg:  nextFwdMsg,
	}, nil
}
