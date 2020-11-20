package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	ownerSidStr := os.Args[1]
	groupSidStr := os.Args[2]
	if err := run(ownerSidStr, groupSidStr); err != nil {
		panic(err)
	}
}

//not clear what these are. Probably ControlFlags
var rawSDPrefixTemplate = []byte{0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func run(ownerSid, groupSid string) error {
	ownerSidBytes, err := sidStrToRaw(ownerSid)
	if err != nil {
		return err
	}

	groupSidBytes, err := sidStrToRaw(groupSid)
	if err != nil {
		return err
	}

	rawSDHeader := rawSDPrefixTemplate

	//group offset position
	rawSDHeader[8] = byte(len(rawSDPrefixTemplate) + len(ownerSidBytes))

	//compose into O:<SID>:G<SID> equivalent
	rawSDBytes := append(rawSDHeader, append(ownerSidBytes, groupSidBytes...)...)

	rawSDBase64 := base64.StdEncoding.EncodeToString(rawSDBytes)
	fmt.Println(rawSDBase64)

	return nil
}

func sidStrToRaw(ownerSid string) ([]byte, error) {
	var sidBytes []byte

	//1-byte revision
	sidBytes = append(sidBytes, 0x01)

	sidParts := strings.Split(ownerSid, "-")

	//1-byte subauthority count
	subAuthorityCount := len(sidParts[3:])
	sidBytes = append(sidBytes, byte(subAuthorityCount))

	//6-byte authority field (big-endian)
	authorityBytes := make([]byte, 6)
	authorityInt, err := strconv.Atoi(sidParts[2])
	if err != nil {
		return nil, err
	}

	//write 32bit int to the last 32 bits (offset 2-bytes)
	binary.BigEndian.PutUint32(authorityBytes[2:], uint32(authorityInt))

	sidBytes = append(sidBytes, authorityBytes...)

	//4-byte subauthority fields (little-endian)
	for _, subAuthorityPart := range sidParts[3:] {
		subAuthorityBytes := make([]byte, 4)

		subAuthorityInt, err := strconv.Atoi(subAuthorityPart)
		if err != nil {
			return nil, err
		}

		//write 32bit int
		binary.LittleEndian.PutUint32(subAuthorityBytes, uint32(subAuthorityInt))

		sidBytes = append(sidBytes, subAuthorityBytes...)
	}

	return sidBytes, nil
}
