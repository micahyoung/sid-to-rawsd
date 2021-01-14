package accesscontrol

import (
	"encoding/binary"
	"strconv"
	"strings"
)


func StringToSid(sidStr string) (*SID, error) {
	sid := &SID{
		revision: 0x1,
	}

	sidParts := strings.Split(sidStr, "-")

	sid.subAuthorityCount = uint8(len(sidParts[3:]))

	authorityInt, err := strconv.Atoi(sidParts[2])
	if err != nil {
		return nil, err
	}
	sid.authority = uint32(authorityInt)

	for _, subAuthorityPart := range sidParts[3:] {
		subAuthorityInt, err := strconv.Atoi(subAuthorityPart)
		if err != nil {
			return nil, err
		}

		sid.subAuthorities = append(sid.subAuthorities, uint32(subAuthorityInt))
	}

	return sid, nil
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
type SID struct {
	revision          byte
	subAuthorityCount uint8
	authority         uint32
	subAuthorities    []uint32
}

func (s *SID) Bytes() []byte {
	var sidBytes []byte

	//1-byte revision
	sidBytes = append(sidBytes, s.revision)

	//1-byte subauthority count
	sidBytes = append(sidBytes, s.subAuthorityCount)

	//6-byte authority field (big-endian)
	authorityBytes := make([]byte, 6)

	//write 32bit int to the last 32 bits (offset 2-bytes)
	binary.BigEndian.PutUint32(authorityBytes[2:], s.authority)

	sidBytes = append(sidBytes, authorityBytes...)

	//4-byte subauthority fields (little-endian)
	for _, subAuthority := range s.subAuthorities {
		subAuthorityBytes := make([]byte, 4)

		//write 32bit int
		binary.LittleEndian.PutUint32(subAuthorityBytes, subAuthority)

		sidBytes = append(sidBytes, subAuthorityBytes...)
	}

	return sidBytes
}
