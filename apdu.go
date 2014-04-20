package main 

const (
	apduMaxExtended = 0xffff + 1
	apduMaxShort = 0xff + 1

	leWildcard = -1
	leWildcardExtended = -2
)

func encodeLength(n int, extended, first bool) []byte {
	var encoded []byte

	if n == leWildcard || n == leWildcardExtended {
		if extended {
			if first {
				return []byte{0,0,0}
			}
			return []byte{0,0}
		} 
		return []byte{0}
	}

	if n < 0 || n > apduMaxExtended {
		panic("apdu length out of range")
	}

	if n > 0 {
		if extended {
			if first {
				encoded = append(encoded, 0)
			}

			if n == apduMaxExtended {
				encoded = append(encoded, 0)
				encoded = append(encoded, 0)

			} else {
				encoded = append(encoded, byte(n>>8))
				encoded = append(encoded, byte(n))
			}

		} else {
			if n == apduMaxShort {
				encoded = append(encoded, 0)
			} else {
				encoded = append(encoded, byte(n))
			}
		}
	}

	return encoded

}

func EncodeAPDU(cla, ins, p1, p2 byte, data []byte, le int) []byte {
	var apdu []byte
	var extended = len(data) > apduMaxShort || le > apduMaxShort || le == leWildcardExtended

	apdu = append(apdu, cla, ins, p1, p2)
	apdu = append(apdu, encodeLength(len(data), extended, true)...)
	apdu = append(apdu, data...)
	apdu = append(apdu, encodeLength(le, extended, len(data) == 0)...)

	return apdu
}

func DecodeResponseAPDU(data []byte) (uint16, []byte) {
	if len(data) < 2 {
		panic("response apdu too short")
	}
	sw := uint16(data[len(data)-2]) << 8 | uint16(data[len(data)-1])
	if len(data) > 2 {
		return sw, data[:len(data)-2]
	} else {
		return sw, nil
	}
}
