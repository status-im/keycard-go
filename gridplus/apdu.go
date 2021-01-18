package gridplus

import (
	"crypto/ecdsa"
	"errors"

	"github.com/GridPlus/keycard-go/apdu"
	log "github.com/sirupsen/logrus"
)

var (
	SafecardAID                                   = []byte{0xA0, 0x00, 0x00, 0x08, 0x20, 0x00, 0x01, 0x01}
	SAFECARD_APDU_CLA_ENCRYPTED_PROPRIETARY uint8 = 0x80
	SAFECARD_APDU_INS_PAIR                  uint8 = 0x12
	PAIR_STEP1                              uint8 = 0x00
	PAIR_STEP2                              uint8 = 0x01
	TLV_TYPE_CUSTOM                         uint8 = 0x80
)

var ErrCardUninitialized = errors.New("card uninitialized")

type SafecardRAPDUStep1 struct {
	SafecardSalt []byte
	SafecardCert SafecardCert
	SafecardSig  []byte
}

type SafecardCert struct {
	Permissions []byte
	PubKey      []byte
	Sig         []byte
}

type SafecardRAPDUStep2 struct {
	PairingIdx int
	Salt       []byte
}

//Manually parse possible TLV responses
func ParseSelectResponse(resp []byte) (instanceUID []byte, cardPubKey []byte, err error) {
	if len(resp) == 0 {
		return nil, nil, errors.New("received nil response")
	}
	switch resp[0] {
	//Initialized
	case 0xA4:
		log.Debug("card wallet initialized")
		//If length of length is set this is a long format TLV response
		if len(resp) < 88 {
			log.Error("response should have been at least length 86 bytes, was length: ", len(resp))
			return nil, nil, errors.New("invalid response length")
		}
		if resp[3] == 0x81 {
			instanceUID = resp[6:22]
			cardPubKey = resp[24:89]
		} else {
			instanceUID = resp[5:21]
			cardPubKey = resp[22:87]
		}
	case 0x80:
		log.Error("card wallet uninitialized")
		return nil, nil, ErrCardUninitialized
	}

	return instanceUID, cardPubKey, nil
}

func NewAPDUPairStep1(clientSalt []byte, pubKey *ecdsa.PublicKey) *apdu.Command {
	pubKeyBytes := SerializePubKey(*pubKey)

	payload := append(clientSalt, TLV_TYPE_CUSTOM, byte(len(pubKeyBytes)))
	payload = append(payload, pubKeyBytes...)

	log.Debug("payload length: ", len(payload))
	return apdu.NewCommand(
		SAFECARD_APDU_CLA_ENCRYPTED_PROPRIETARY,
		SAFECARD_APDU_INS_PAIR,
		PAIR_STEP1,
		0x00,
		payload,
	)
}

func ParsePairStep1Response(resp []byte) (apduResp SafecardRAPDUStep1, err error) {
	apduResp.SafecardSalt = resp[0:32]
	certLength := int(resp[33])

	apduResp.SafecardCert = SafecardCert{
		Permissions: resp[34:38],                   //skip 2 byte TLV header, include 2 byte TLV field description
		PubKey:      resp[38 : 38+2+65],            //2 byte TLV, 65 byte pubkey
		Sig:         resp[38+65+2 : 34+certLength], //sig can be 72 to 74 bytes
	}

	log.Debugf("end of resp len(%v): % X", len(resp[34+certLength:]), resp[34+certLength:])
	apduResp.SafecardSig = resp[34+certLength:]

	log.Debugf("card salt length(%v):\n% X", len(apduResp.SafecardSalt), apduResp.SafecardSalt)
	log.Debugf("card cert permissions length(%v):\n% X", len(apduResp.SafecardCert.Permissions), apduResp.SafecardCert.Permissions)
	log.Debugf("card cert pubKey length(%v):\n% X", len(apduResp.SafecardCert.PubKey), apduResp.SafecardCert.PubKey)
	log.Debugf("card cert sig length(%v):\n% X", len(apduResp.SafecardCert.Sig), apduResp.SafecardCert.Sig)

	log.Debugf("card sig length(%v): % X", len(apduResp.SafecardSig), apduResp.SafecardSig)
	return apduResp, nil
}

func NewAPDUPairStep2(cryptogram []byte) *apdu.Command {
	return apdu.NewCommand(
		SAFECARD_APDU_CLA_ENCRYPTED_PROPRIETARY,
		SAFECARD_APDU_INS_PAIR,
		PAIR_STEP2,
		0x00,
		cryptogram,
	)
}

func ParsePairStep2Response(resp []byte) (SafecardRAPDUStep2, error) {
	log.Debugf("raw pairStep2 resp: % X", resp)
	correctLength := 33
	if len(resp) != correctLength {
		log.Errorf("resp was length(%v). should have been length %v", len(resp), correctLength)
		return SafecardRAPDUStep2{}, errors.New("pairstep2 response was invalid length")
	}
	return SafecardRAPDUStep2{
		PairingIdx: int(resp[0]),
		Salt:       resp[1:33],
	}, nil
}

func ParseExportSeedResponse(resp []byte) ([]byte, error) {
	if len(resp) != 66 {
		return nil, errors.New("export seed response invalid length")
	}
	return resp[2:], nil
}
