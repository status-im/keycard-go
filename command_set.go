package keycard

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/GridPlus/keycard-go/apdu"
	"github.com/GridPlus/keycard-go/crypto"
	"github.com/GridPlus/keycard-go/globalplatform"
	"github.com/GridPlus/keycard-go/gridplus"
	"github.com/GridPlus/keycard-go/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)

var ErrNoAvailablePairingSlots = errors.New("no available pairing slots")

type CommandSet struct {
	c               types.Channel
	sc              *SecureChannel
	ApplicationInfo *types.ApplicationInfo
	PairingInfo     *types.PairingInfo
}

func NewCommandSet(c types.Channel) *CommandSet {
	return &CommandSet{
		c:               c,
		sc:              NewSecureChannel(c),
		ApplicationInfo: &types.ApplicationInfo{},
	}
}

func (cs *CommandSet) SetPairingInfo(key []byte, index int) {
	cs.PairingInfo = &types.PairingInfo{
		Key:   key,
		Index: index,
	}
}

func (cs *CommandSet) Select() error {
	var SafecardAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x20, 0x00, 0x01, 0x01}
	cmd := globalplatform.NewCommandSelect(SafecardAID)
	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)
	if err != nil {
		log.Error("could not send select command. err: ", err)
		return err
	}

	log.Debug("select response:\n", hex.Dump(resp.Data))
	instanceUID, cardPubKey, err := gridplus.ParseSelectResponse(resp.Data)
	if err != nil {
		return err
	}
	log.Debugf("instanceUID: % X", instanceUID)
	log.Debugf("select response pubKey: % X", cardPubKey)

	//Generating secure channel secrets here in advance of pairing and opening channel
	err = cs.sc.GenerateSecret(cardPubKey)
	if err != nil {
		log.Error("unable to generate secure channel secrets. err: ", err)
		return err
	}

	return nil
}

func (cs *CommandSet) Init(secrets *Secrets) error {
	data, err := cs.sc.OneShotEncrypt(secrets)
	if err != nil {
		return err
	}

	init := NewCommandInit(data)
	resp, err := cs.c.Send(init)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) Pair() error {
	//Generate random salt and keypair
	clientSalt := make([]byte, 32)
	rand.Read(clientSalt)

	pairingPrivKey, err := ethcrypto.GenerateKey()
	if err != nil {
		log.Error("unable to generate pairing keypair. err: ", err)
		return err
	}
	pairingPubKey := pairingPrivKey.PublicKey

	//Exchange pairing key info with card
	cmd := gridplus.NewAPDUPairStep1(clientSalt, &pairingPubKey)
	resp, err := cs.c.Send(cmd)
	if err != nil {
		log.Error("unable to send Pair Step 1 command. err: ", err)
		return err
	}
	pairStep1Resp, err := gridplus.ParsePairStep1Response(resp.Data)
	if err != nil {
		log.Error("could not parse pair step 2 response. err: ", err)
	}

	//Validate card's certificate has valid GridPlus signature
	certValid := gridplus.ValidateCardCertificate(pairStep1Resp.SafecardCert)
	log.Debug("certificate signature valid: ", certValid)
	if !certValid {
		log.Error("unable to verify card certificate.")
		return err
	}
	log.Debug("pair step 2 safecard cert:\n", hex.Dump(pairStep1Resp.SafecardCert.PubKey))

	cardCertPubKey, err := gridplus.ParseCertPubkeyToECDSA(pairStep1Resp.SafecardCert.PubKey)
	if err != nil {
		log.Error("unable to parse certificate public key. err: ", err)
		return err
	}

	pubKeyValid := gridplus.ValidateECCPubKey(cardCertPubKey)
	log.Debug("certificate public key valid: ", pubKeyValid)
	if !pubKeyValid {
		log.Error("card pubkey invalid")
		return err
	}

	//challenge message test
	ecdhSecret := crypto.GenerateECDHSharedSecret(pairingPrivKey, cardCertPubKey)

	secretHashArray := sha256.Sum256(append(clientSalt, ecdhSecret...))
	secretHash := secretHashArray[0:]

	type ECDSASignature struct {
		R, S *big.Int
	}
	signature := &ECDSASignature{}
	_, err = asn1.Unmarshal(pairStep1Resp.SafecardSig, signature)
	if err != nil {
		log.Error("could not unmarshal certificate signature.", err)
	}

	//validate that card created valid signature over same salted and hashed ecdh secret
	valid := ecdsa.Verify(cardCertPubKey, secretHash, signature.R, signature.S)
	if !valid {
		log.Error("ecdsa sig not valid")
		return errors.New("could not verify shared secret challenge")
	}
	log.Debug("card signature on challenge message valid: ", valid)

	cryptogram := sha256.Sum256(append(pairStep1Resp.SafecardSalt, secretHash...))

	cmd = gridplus.NewAPDUPairStep2(cryptogram[0:])
	resp, err = cs.c.Send(cmd)
	if err != nil {
		log.Error("error sending pair step 2 command. err: ", err)
		return err
	}

	pairStep2Resp, err := gridplus.ParsePairStep2Response(resp.Data)
	if err != nil {
		log.Error("could not parse pair step 2 response. err: ", err)
	}
	log.Debugf("pairStep2Resp: % X", pairStep2Resp)

	//Derive Pairing Key
	pairingKey := sha256.Sum256(append(pairStep2Resp.Salt, secretHash...))
	log.Debugf("derived pairing key: % X", pairingKey)

	//Store pairing info for use in OpenSecureChannel
	cs.SetPairingInfo(pairingKey[0:], pairStep2Resp.PairingIdx)

	return nil
}

func (cs *CommandSet) Unpair(index uint8) error {
	cmd := NewCommandUnpair(index)
	resp, err := cs.sc.Send(cmd)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) OpenSecureChannel() error {
	if cs.ApplicationInfo == nil {
		return errors.New("cannot open secure channel without setting PairingInfo")
	}

	cmd := NewCommandOpenSecureChannel(uint8(cs.PairingInfo.Index), cs.sc.RawPublicKey())
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	encKey, macKey, iv := crypto.DeriveSessionKeys(cs.sc.Secret(), cs.PairingInfo.Key, resp.Data)
	cs.sc.Init(iv, encKey, macKey)

	err = cs.mutualAuthenticate()
	if err != nil {
		return err
	}

	return nil
}

func (cs *CommandSet) GetStatus(info uint8) (*types.ApplicationStatus, error) {
	cmd := NewCommandGetStatus(info)
	resp, err := cs.sc.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseApplicationStatus(resp.Data)
}

func (cs *CommandSet) GetStatusApplication() (*types.ApplicationStatus, error) {
	return cs.GetStatus(P1GetStatusApplication)
}

func (cs *CommandSet) GetStatusKeyPath() (*types.ApplicationStatus, error) {
	return cs.GetStatus(P1GetStatusKeyPath)
}

func (cs *CommandSet) VerifyPIN(pin string) error {
	cmd := NewCommandVerifyPIN(pin)
	resp, err := cs.sc.Send(cmd)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) ChangePIN(pin string) error {
	cmd := NewCommandChangePIN(pin)
	resp, err := cs.sc.Send(cmd)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) ChangePUK(puk string) error {
	cmd := NewCommandChangePUK(puk)
	resp, err := cs.sc.Send(cmd)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) ChangePairingSecret(password string) error {
	secret := generatePairingToken(password)
	cmd := NewCommandChangePairingSecret(secret)
	resp, err := cs.sc.Send(cmd)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) GenerateKey() ([]byte, error) {
	cmd := NewCommandGenerateKey()
	resp, err := cs.sc.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func (cs *CommandSet) RemoveKey() error {
	cmd := NewCommandRemoveKey()
	resp, err := cs.sc.Send(cmd)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) DeriveKey(path string) error {
	cmd, err := NewCommandDeriveKey(path)
	if err != nil {
		return err
	}

	resp, err := cs.sc.Send(cmd)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) ExportKey(derive bool, makeCurrent bool, onlyPublic bool, path string) ([]byte, error) {
	var p1 uint8
	if derive == false {
		p1 = P1ExportKeyCurrent
	} else if makeCurrent == false {
		p1 = P1ExportKeyDerive
	} else {
		p1 = P1ExportKeyDeriveAndMakeCurrent
	}
	var p2 uint8
	if onlyPublic == true {
		p2 = P2ExportKeyPublicOnly
	} else {
		p2 = P2ExportKeyPrivateAndPublic
	}
	cmd, err := NewCommandExportKey(p1, p2, path)
	if err != nil {
		return nil, err
	}

	resp, err := cs.sc.Send(cmd)
	err = cs.checkOK(resp, err)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (cs *CommandSet) ExportSeed() ([]byte, error) {
	cmd := NewCommandExportSeed()
	resp, err := cs.sc.Send(cmd)
	if err != nil {
		return nil, err
	}
	seed, err := gridplus.ParseExportSeedResponse(resp.Data)
	if err != nil {
		return nil, err
	}
	return seed, nil
}

func (cs *CommandSet) SetPinlessPath(path string) error {
	cmd, err := NewCommandSetPinlessPath(path)
	if err != nil {
		return err
	}

	resp, err := cs.sc.Send(cmd)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) Sign(data []byte) (*types.Signature, error) {
	cmd, err := NewCommandSign(data, P1SignCurrentKey, "")
	if err != nil {
		return nil, err
	}

	resp, err := cs.sc.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}

func (cs *CommandSet) SignWithPath(data []byte, path string) (*types.Signature, error) {
	cmd, err := NewCommandSign(data, P1SignDerive, path)
	if err != nil {
		return nil, err
	}

	resp, err := cs.sc.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}

func (cs *CommandSet) SignPinless(data []byte) (*types.Signature, error) {
	cmd, err := NewCommandSign(data, P1SignPinless, "")
	if err != nil {
		return nil, err
	}

	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}

func (cs *CommandSet) LoadSeed(seed []byte) ([]byte, error) {
	cmd := NewCommandLoadSeed(seed)
	resp, err := cs.sc.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func (cs *CommandSet) mutualAuthenticate() error {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return err
	}

	cmd := NewCommandMutuallyAuthenticate(data)
	resp, err := cs.sc.Send(cmd)

	return cs.checkOK(resp, err)
}

func (cs *CommandSet) checkOK(resp *apdu.Response, err error, allowedResponses ...uint16) error {
	if err != nil {
		return err
	}

	if len(allowedResponses) == 0 {
		allowedResponses = []uint16{apdu.SwOK}
	}

	for _, code := range allowedResponses {
		if code == resp.Sw {
			return nil
		}
	}

	return apdu.NewErrBadResponse(resp.Sw, "unexpected response")
}
