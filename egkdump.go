package main

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"

	"code.google.com/p/go-charset/charset"
	_ "code.google.com/p/go-charset/data"
	"github.com/ebfe/scard"
	"github.com/kr/pretty"
)

var (
	aidRootMF = []byte{0xd2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x00}
	aidHCA    = []byte{0xd2, 0x76, 0x00, 0x00, 0x01, 0x02}
	aidQES    = []byte{0xd2, 0x76, 0x00, 0x00, 0x66, 0x01}
	aidEsign  = []byte{0xa0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4e}
)

const (
	efatr            = 0x1d
	efdir            = 0x1e
	efcaegkcsr2048   = 0x04
	efcaegkcse256    = 0x07
	efcaegkcse384    = 0x0d
	efegkautcvcr2048 = 0x03
	efegkautcvce256  = 0x06
	efegkautcvce384  = 0x0c
	efgdo            = 0x02
	efversion        = 0x10

	efstatusvd = 0x0c
	efpd       = 0x01
	efvd       = 0x02

	efcchaut = 1
	efcchenc = 2
)

type Card interface {
	Transmit(cmd []byte) ([]byte, error)
}

type cardError uint16

func (ce cardError) Error() string {
	return fmt.Sprintf("sw=%x", uint16(ce))
}

type apduLogger struct {
	card Card
	log  io.Writer
}

func newApduLogger(card Card, log io.Writer) Card {
	return &apduLogger{card: card, log: log}
}

func (al *apduLogger) Transmit(cmd []byte) ([]byte, error) {
	fmt.Fprintf(al.log, "c-apdu: %x\n", cmd)
	rsp, err := al.card.Transmit(cmd)
	if rsp != nil {
		fmt.Fprintf(al.log, "r-apdu: %x\n", rsp)
	}
	return rsp, err
}

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

func selectAid(card Card, aid []byte) error {
	apdu := EncodeAPDU(0x00, 0xa4, 0x04, 0x0c, aid, 0)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return err
	}
	sw, _ := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return cardError(sw)
	}
	return nil
}

func readBinary(card Card, offset uint16, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb0, byte(offset>>8), byte(offset), nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, cardError(sw)
	}
	return data, nil
}

func readBinarySfid(card Card, sfid byte, offset byte, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb0, 0x80|sfid, offset, nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, cardError(sw)
	}
	return data, nil
}

func readRecord(card Card, idx byte, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb2, idx, 0x04, nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, cardError(sw)
	}
	return data, nil
}

func readRecordSfid(card Card, sfid byte, idx byte, le int) ([]byte, error) {
	apdu := EncodeAPDU(0x00, 0xb2, idx, (sfid<<3)|0x04, nil, le)
	rapdu, err := card.Transmit(apdu)
	if err != nil {
		return nil, err
	}
	sw, data := DecodeResponseAPDU(rapdu)
	if sw != 0x9000 {
		return nil, cardError(sw)
	}
	return data, nil
}

func checkBCD(raw []byte) bool {
	for _, b := range raw {
		if b>>4 > 9 || b&0xf > 9 {
			return false
		}
	}
	return true
}

func decodeBCD(raw []byte) uint64 {
	var x uint64

	for _, b := range raw {
		x *= 10
		x += uint64(b >> 4)
		x *= 10
		x += uint64(b & 0xf)
	}

	return x
}

func parseBCDVersion(raw []byte) string {
	if len(raw) != 5 || !checkBCD(raw) {
		return "<invalid>"
	}
	x := decodeBCD(raw)
	return fmt.Sprintf("%d.%d.%d", x/(10000*1000), (x/10000)%1000, x%10000)
}

type ICCSN struct {
	MajorIndustryIdentifier byte
	CountryCode             int
	IssuerIdentifier        int
	SerialNumber            int
}

func (sn *ICCSN) UnmarshalBinary(raw []byte) error {
	if len(raw) != 10 {
		return fmt.Errorf("too short")
	}

	sn.MajorIndustryIdentifier = raw[0]
	x := decodeBCD(raw[1:])
	sn.CountryCode = int(x / 1000000000000000)
	sn.IssuerIdentifier = int((x / 10000000000) % 100000)
	sn.SerialNumber = int(x % 10000000000)

	return nil
}

func parseGDO(raw []byte) (*ICCSN, error) {
	if len(raw) != 12 {
		return nil, fmt.Errorf("too short")
	}

	if raw[0] != 0x5a {
		return nil, fmt.Errorf("bad tag (%x)", raw[0])
	}
	if raw[1] != 0x0a {
		return nil, fmt.Errorf("invalid length (%x)", raw[1])
	}

	var sn ICCSN
	err := sn.UnmarshalBinary(raw[2:])
	if err != nil {
		return nil, err
	}
	return &sn, nil
}

func dumpRoot(card Card) {
	fmt.Println("mf/ef.atr")
	atr, err := readBinarySfid(card, efatr, 0, apduMaxShort)
	if err != nil {
		fmt.Printf("\terr: %s\n", err)
	} else {
		fmt.Printf("\t%s\n", hex.EncodeToString(atr))
	}

	fmt.Println("mf/ef.dir")
	for i := byte(1); i < 11; i++ {
		dir, err := readRecordSfid(card, efdir, i, apduMaxShort)
		if err != nil {
			fmt.Printf("\t[%d] err: %s\n", i, err)
		} else {
			fmt.Printf("\t[%d]: %s\n", i, hex.EncodeToString(dir))
		}
	}

	fmt.Println("mf/ef.gdo")
	gdo, err := readBinarySfid(card, efgdo, 0, apduMaxShort)
	if err != nil {
		fmt.Printf("\terr: %s\n", err)
	} else {
		fmt.Printf("\t%s\n", hex.EncodeToString(gdo))
		sn, err := parseGDO(gdo)
		if err != nil {
			fmt.Printf("\tparse error: %s\n", err)
		} else {
			pretty.Printf("\t%# v\n", sn)
		}
	}

	fmt.Println("mf/ef.version")
	for i := byte(1); i < 5; i++ {
		version, err := readRecordSfid(card, efversion, i, apduMaxShort)
		if err != nil {
			fmt.Printf("\t[%d] err: %s\n", i, err)
		} else {
			fmt.Printf("\t[%d]: %s // %q\n", i, hex.EncodeToString(version), parseBCDVersion(version))
		}
	}

	var certs = []struct {
		name string
		sfid byte
	}{
		{name: "mf/ef.c.ca_egk.cs.r2048", sfid: efcaegkcsr2048},
		{name: "mf/ef.c.ca_egk.cs.e256", sfid: efcaegkcse256},
		{name: "mf/ef.c.ca_egk.cs.e384", sfid: efcaegkcse384},
		{name: "mf/ef.c.egk.aut_cvc.r2048", sfid: efegkautcvcr2048},
		{name: "mf/ef.c.egk.aut_cvc.e256", sfid: efegkautcvce256},
		{name: "mf/ef.c.egk.aut_cvc.e384", sfid: efegkautcvce384},
	}

	for _, c := range certs {
		fmt.Println(c.name)
		raw, err := readBinarySfid(card, c.sfid, 0, apduMaxExtended)
		if err != nil {
			fmt.Printf("\terr: %s\n", err)
		} else {
			fmt.Print(hex.Dump(raw))
		}
	}
}

type StatusVD struct {
	Status    string
	Timestamp string
	Version   string
	Reserved  [5]byte
}

func (s *StatusVD) UnmarshalBinary(raw []byte) error {
	if len(raw) != 25 {
		return fmt.Errorf("invalid length")
	}

	s.Status = string([]byte{raw[0]})
	s.Timestamp = string(raw[1:15])
	s.Version = parseBCDVersion(raw[15:20])
	copy(s.Reserved[:], raw[20:])

	return nil
}

func parseGzippedXml(raw []byte, v interface{}) error {
	rd, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	//dec := xml.NewDecoder(io.TeeReader(rd, os.Stdout))
	dec := xml.NewDecoder(rd)
	dec.CharsetReader = charset.NewReader
	return dec.Decode(v)
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
					Wohnsitzlaendercode string `xml:"Wohnsitzlaendercode"`
				} `xml:"Land"`
			} `xml:"PostfachAdresse"`
			StrassenAdresse struct {
				Postleitzahl string `xml:"Postleitzahl"`
				Ort          string `xml:"Ort"`
				Postfach     string `xml:"Postfach"`
				Land         struct {
					Wohnsitzlaendercode string `xml:"Wohnsitzlaendercode"`
				} `xml:"Land"`
				Strasse           string `xml:"Strasse"`
				Hausnummer        string `xml:"Hausnummer"`
				Anschriftenzusatz string `xml:"Anschriftenzusatz"`
			} `xml:"StrassenAdresse"`
		} `xml:"Person"`
	} `xml:"Versicherter"`
}

func (pd *PD) UnmarshalBinary(raw []byte) error {
	return parseGzippedXml(raw, pd)
}

type VD struct {
	CDMVersion   string `xml:"CDM_VERSION,attr"`
	Versicherter struct {
		Versicherungsschutz struct {
			Beginn        string `xml:"Beginn"`
			Ende          string `xml:"Ende"`
			Kostentraeger struct {
				Kostentraegerkennung      string `xml:"Kostentraegerkennung"`
				Kostentraegerlaendercode  string `xml:"Kostentraegerlaendercode"`
				Name                      string `xml:"Name"`
				AbrechnenderKostentraeger struct {
					Kostentraegerkennung string `xml:"Kostentraegerkennung"`
					Name                 string `xml:"Name"`
				} `xml:"AbrechnenderKostentraeger"`
			} `xml:"Kostentraeger"`
		} `xml:"Versicherungsschutz"`
		Zusatzinfos struct {
			ZusatzinfosGKV struct {
				Rechtskreis              string `xml:"Rechtskreis"`
				Versichertenart          string `xml:"Versichertenart"`
				VersichertenstatusRSA    string `xml:"Versichertenstatus_RSA"`
				ZusatzinfosAbrechnungGKV struct {
					KostenerstattungAmbulant   string `xml:"Kostenerstattung_ambulant"`
					KostenerstattungStationaer string `xml:"Kostenerstattung_stationaer"`
					WOP                        string `xml:"WOP"`
				} `xml:"Zusatzinfos_Abrechnung_GKV"`
			} `xml:"ZusatzinfosGKV"`
			ZusatzinfosPKV struct {
				PKVVerbandstarif     string `xml:"PKV_Verbandstarif"`
				Beihilfeberechtigung struct {
					Kennzeichnung string `xml:"Kennzeichnung"`
				} `xml:"Beihilfeberechtigung"`
				StationaereLeistungen struct {
					StationaereWahlleistungUnterkunft           string `xml:"Stationaere_Wahlleistung_Unterkunft"`
					ProzentwertWahlleistungUnterkunft           string `xml:"Prozentwert_Wahlleistung_Unterkunft"`
					HoechstsatzWahlleistungUnterkunft           string `xml:"HoechstsatzWahlleistungUnterkunft"`
					StationaereWahlleistungAerztlicheBehandlung string `xml:"Stationaere_Wahlleistung_aerztliche_Behandlung"`
					ProzentwertWahlleistungAerztlicheBehandlung string `xml:"Prozentwert_Wahlleistung_aerztliche_Behandlung"`
					TeilnahmeClinicCardVerfahren                string `xml:"Teilnahme_ClinicCard_Verfahren"`
				} `xml:"StationaereLeistungen"`
			} `xml:"ZusatzinfosPKV"`
		} `xml:"Zusatzinfos"`
	} `xml:"Versicherter"`
}

func (vd *VD) UnmarshalBinary(raw []byte) error {
	return parseGzippedXml(raw, vd)
}

type GVD struct {
	CDMVersion       string `xml:"CDM_VERSION,attr"`
	Zuzahlungsstatus struct {
		Status     string `xml:"Status"`
		GueltigBis string `xml:"Gueltig_bis"`
	} `xml:"Zuzahlungsstatus"`
	BesonderePersonengruppe string `xml:"Besondere_Personengruppe"`
	DMPKennzeichnung        string `xml:"DMP_Kennzeichnung"`
}

func (gvd *GVD) UnmarshalBinary(raw []byte) error {
	return parseGzippedXml(raw, gvd)
}

func dumpHCA(card Card) {
	fmt.Println("hca/ef.statusvd")
	statusvd, err := readBinarySfid(card, efstatusvd, 0, apduMaxExtended)
	if err != nil {
		fmt.Printf("hca/ef.statusvd err: %s\n", err)
	} else {
		var svd StatusVD
		err := svd.UnmarshalBinary(statusvd)
		if err != nil {
			fmt.Printf("parse err: %s\n", err)
		} else {
			pretty.Printf("%# v\n", svd)
		}
	}

	fmt.Println("hca/ef.pd")
	rawpd, err := readBinarySfid(card, efpd, 0, apduMaxExtended)
	if err != nil {
		fmt.Printf("\terr: %s\n", err)
	} else {
		if len(rawpd) < 2 {
			fmt.Printf("pd data too short")
		}

		pdlen := int(binary.BigEndian.Uint16(rawpd))
		if pdlen > len(rawpd)-2 {
			fmt.Printf("pd invalid length %d (avail %d)\n", pdlen, len(rawpd))
		}

		var pd PD
		err := pd.UnmarshalBinary(rawpd[2 : 2+pdlen])
		if err != nil {
			fmt.Printf("\tparse error: %s\n", err)
			fmt.Println(hex.Dump(rawpd))
		} else {
			pretty.Println(pd)
		}
	}

	fmt.Println("hca/ef.vd")
	raw, err := readBinarySfid(card, efvd, 0, apduMaxExtended)
	if err != nil {
		fmt.Printf("\terr: %s\n", err)
	} else {
		if len(raw) < 8 {
			fmt.Printf("ef.vd data too short")
			fmt.Println(hex.Dump(raw))
		}

		vdstart := int(binary.BigEndian.Uint16(raw))
		vdend := int(binary.BigEndian.Uint16(raw[2:]))
		gvdstart := int(binary.BigEndian.Uint16(raw[4:]))
		gvdend := int(binary.BigEndian.Uint16(raw[6:]))

		if vdend < vdstart || vdend > len(raw) {
			fmt.Printf("ef.vd vd invalid start/end offset %d/%d (avail %d)\n", vdstart, vdend, len(raw))
		}
		var vd VD
		vdraw := raw[vdstart:vdend]
		err := vd.UnmarshalBinary(vdraw)
		if err != nil {
			fmt.Printf("\tparse error: %s\n", err)
			fmt.Println(hex.Dump(vdraw))
		} else {
			pretty.Println(vd)
		}

		if gvdend < gvdstart || gvdend > len(raw) {
			fmt.Printf("ef.gvd gvd invalid start/end offset %d/%d (avail %d)\n", gvdstart, gvdend, len(raw))
		}
		var gvd GVD
		gvdraw := raw[gvdstart:gvdend]
		gvd.UnmarshalBinary(gvdraw)
		if err != nil {
			fmt.Printf("\tparse error: %s\n", err)
			fmt.Println(hex.Dump(gvdraw))
		} else {
			pretty.Println(gvd)
		}
	}
}

func readBinaryFull(card Card, sfid byte) ([]byte, error) {
	// FIXME: this sucks
	raw, err := readBinarySfid(card, efcchaut, 0, apduMaxExtended)
	if err != nil {
		return nil, err
	}
	for len(raw) < 1<<16 {
		buf, err := readBinary(card, uint16(len(raw)), apduMaxExtended)
		if err != nil {
			if cerr, ok := err.(cardError); ok {
				if cerr == 0x6b00 {
					return append(raw, buf...), nil
				}
			}
			return nil, err
		}
		raw = append(raw, buf...)
	}
	return raw, nil
}

func parseCert(raw []byte) (*x509.Certificate, error) {
	// strip trailing zeroes...
	var val asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &val)
	if err != nil {
		return nil, err
	}

	for _, b := range rest {
		if b != 0 {
			return nil, fmt.Errorf("parseCert: non-zero trailing bytes in cert")
		}
	}
	return x509.ParseCertificate(val.FullBytes)
}

func dumpEsign(card Card) {
	fmt.Println("esign/ef.c.ch.aut")
	var raw []byte
	raw, err := readBinaryFull(card, efcchaut)
	if err != nil {
		fmt.Printf("\terr: %s\n", err)
	} else {
		cert, err := parseCert(raw)
		if err != nil {
			fmt.Printf("\terr: %s\n", err)
			fmt.Print(hex.Dump(raw))
		} else {
			fmt.Printf("\tsubject: %s\n", cert.Subject)
			fmt.Printf("\tissuer: %s\n", cert.Issuer)
			fmt.Print(hex.Dump(cert.Raw))
		}
	}
	fmt.Println("esign/ef.c.ch.enc")
	raw, err = readBinaryFull(card, efcchenc)
	if err != nil {
		fmt.Printf("\terr: %s\n", err)
	} else {
		cert, err := parseCert(raw)
		if err != nil {
			fmt.Printf("\terr: %s\n", err)
			fmt.Print(hex.Dump(raw))
		} else {
			fmt.Printf("\tsubject: %s\n", cert.Subject)
			fmt.Printf("\tissuer: %s\n", cert.Issuer)
			fmt.Print(hex.Dump(cert.Raw))
		}
	}
}

var desc = []struct {
	name string
	aid  []byte
	fn   func(card Card)
}{
	{
		name: "mf",
		aid:  aidRootMF,
		fn:   dumpRoot,
	}, {
		name: "hca",
		aid:  aidHCA,
		fn:   dumpHCA,
	}, {
		name: "qes",
		aid:  aidQES,
		fn:   nil,
	}, {
		name: "esign",
		aid:  aidEsign,
		fn:   dumpEsign,
	},
}

func main() {
	traceApdus := flag.Bool("t", false, "trace apdus")
	flag.Parse()

	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ctx.Release()

	sccard, err := findCard(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer sccard.Disconnect(scard.ResetCard)

	status, err := sccard.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "card status: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("reader: %s\n", status.Reader)
	fmt.Printf("atr: % x\n", status.Atr)

	var card Card = sccard

	if *traceApdus {
		card = newApduLogger(card, os.Stdout)
	}

	for _, d := range desc {
		fmt.Printf("selecting %s: %x...\n", d.name, d.aid)
		if err := selectAid(card, d.aid); err != nil {
			fmt.Println(err)
		} else {
			if d.fn == nil {
				fmt.Println("\tok")
			} else {
				d.fn(card)
			}
		}
	}
}
