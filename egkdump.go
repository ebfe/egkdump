package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"

	"code.google.com/p/go-charset/charset"
	_ "code.google.com/p/go-charset/data"
	"github.com/ebfe/scard"
	"github.com/kr/pretty"
)

var (
	aidRootMF = []byte{0xd2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x00}
	aidHCA    = []byte{0xd2, 0x76, 0x00, 0x00, 0x01, 0x02}
	aidEsign  = []byte{0xa0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4e}
)

const (
	efatr     = 0x1d
	efgdo     = 0x02
	efversion = 0x10

	efstatusvd = 0x0c
	efpd       = 0x01
	efvd       = 0x02
)

func findCard(ctx *scard.Context) (*scard.Card, error) {
	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, err
	}
	for _, r := range readers {
		card, err := ctx.Connect(r, scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			continue
		}
		return card, nil
	}
	return nil, fmt.Errorf("no card found")
}

func selectAid(card *scard.Card, aid []byte) error {
	apdu := EncodeAPDU(0x00, 0xa4, 0x04, 0x0c, aid, 0)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return err
	}
	sw, _ := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return fmt.Errorf("sw %x\n", sw)
	}
	return nil
}

func readBinary(card *scard.Card, offset uint16, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb0, byte(offset>>8), byte(offset), nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, fmt.Errorf("sw %x\n", sw)
	}
	return data, nil
}

func readBinarySfid(card *scard.Card, sfid byte, offset byte, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb0, 0x80|sfid, offset, nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, fmt.Errorf("sw %x\n", sw)
	}
	return data, nil
}

func readRecord(card *scard.Card, idx byte, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb2, idx, 0x04, nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, fmt.Errorf("sw %x\n", sw)
	}
	return data, nil
}

func readRecordSfid(card *scard.Card, sfid byte, idx byte, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb2, idx, (sfid<<3)|0x04, nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, fmt.Errorf("sw %x\n", sw)
	}
	return data, nil
}

func dumpRoot(card *scard.Card) {
	atr, err := readBinarySfid(card, efatr, 0, leWildcard)
	if err != nil {
		fmt.Printf("ef.atr err: %s\n", err)
	} else {
		fmt.Printf("ef.atr: %s\n", hex.EncodeToString(atr))
	}

	gdo, err := readBinarySfid(card, efgdo, 0, leWildcard)
	if err != nil {
		fmt.Printf("ef.gdo err: %s\n", err)
	} else {
		fmt.Printf("ef.gdo: %s\n", hex.EncodeToString(gdo))
	}

	for i := byte(1); i < 5; i++ {
		version, err := readRecordSfid(card, efversion, i, leWildcard)
		if err != nil {
			fmt.Printf("ef.version[i] err: %s\n", i, err)
		} else {
			fmt.Printf("ef.version[%d]: %s\n", i, hex.EncodeToString(version))
		}
	}

}

type PD struct {
	CDMVersion   string `xml:"CDM_VERSION,attr"`
	Versicherter struct {
		VersichertenID string `xml:"Versicherten_ID"`
		Person         struct {
			Geburtsdatum    string `xml:"Geburtsdatum"`
			Vorname         string `xml:"Vorname"`
			Nachname        string `xml:"Nachname"`
			Geschlecht      string `xml:"Geschlecht"`
			Vorsatzwort     string `xml:"Vorsatzwort"`
			Namenszusatz    string `xml:"Namenszusatz"`
			Titel           string `xml:"Titel"`
			PostfachAdresse struct {
				Postleitzahl string `xml:"Postleitzahl"`
				Ort          string `xml:"Ort"`
				Postfach     string `xml:"Postfach"`
				Land         struct {
					Wohnsitzlaendercode string `xml:"Wohnsitzlaendercode'`
				} `xml:"Land"`
			} `xml:"PostfachAdresse"`
			StrassenAdresse struct {
				Postleitzahl string `xml:"Postleitzahl"`
				Ort          string `xml:"Ort"`
				Postfach     string `xml:"Postfach"`
				Land         struct {
					Wohnsitzlaendercode string `xml:"Wohnsitzlaendercode'`
				} `xml:"Land"`
				Strasse           string `xml:"Strasse"`
				Hausnummer        string `xml:"Hausnummer"`
				Anschriftenzusatz string `xml:"Anschriftenzusatz"`
			} `xml:"StrassenAdresse"`
		} `xml:"Person"`
	} `xml:"Versicherter"`
}

func parsePD(raw []byte) (*PD, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("pd data too short")
	}

	dlen := int(binary.BigEndian.Uint16(raw))
	if dlen > len(raw)-2 {
		return nil, fmt.Errorf("pd invalid length %d (avail %d)\n", dlen, len(raw))
	}

	gzipped := raw[2 : 2+dlen]
	rd, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return nil, err
	}
	var pd PD
	dec := xml.NewDecoder(rd)
	dec.CharsetReader = charset.NewReader
	err = dec.Decode(&pd)
	if err != nil {
		return nil, err
	}
	return &pd, nil
}

func dumpHCA(card *scard.Card) {
	statusvd, err := readBinarySfid(card, efstatusvd, 0, leWildcardExtended)
	if err != nil {
		fmt.Printf("ef.statusvd err: %s\n", err)
	} else {
		fmt.Printf("ef.statusvd: %s\n", hex.EncodeToString(statusvd))
	}

	pd, err := readBinarySfid(card, efpd, 0, leWildcardExtended)
	if err != nil {
		fmt.Printf("ef.pd err: %s\n", err)
	} else {
		fmt.Printf("ef.pd:\n")
		parsed, err := parsePD(pd)
		if err != nil {
			fmt.Printf("parse error: %s\n", err)
			fmt.Println(hex.Dump(pd))
		} else {
			pretty.Println(parsed)
		}
	}

	vd, err := readBinarySfid(card, efvd, 0, leWildcardExtended)
	if err != nil {
		fmt.Printf("ef.vd err: %s\n", err)
	} else {
		fmt.Printf("ef.vd:\n")
		fmt.Println(hex.Dump(vd))
	}
}

func main() {
	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ctx.Release()

	card, err := findCard(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer card.Disconnect(scard.ResetCard)

	status, err := card.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "card status: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("reader: %s\n", status.Reader)
	fmt.Printf("atr: % x\n", status.Atr)

	fmt.Printf("selecting root mf: %x... ", aidRootMF)
	if err := selectAid(card, aidRootMF); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("ok")
		dumpRoot(card)
	}

	fmt.Printf("selecting hca: %x... ", aidHCA)
	if err := selectAid(card, aidHCA); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("ok")
		dumpHCA(card)
	}

	fmt.Printf("selecting esign: %x... ", aidEsign)
	if err := selectAid(card, aidHCA); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("ok")
	}
}
