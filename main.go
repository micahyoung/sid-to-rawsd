package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

//ref: http://www.adamretter.org.uk/blog/entries/active-directory-ldap-users-primary-group.xml
//testdata: https://gist.github.com/micahyoung/7df87d480fd6b1a4cbdcbcbd6ad99324
//mscorlib: https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs

func main() {
	sidStr := os.Args[1]
	if err := run(sidStr); err != nil {
		panic(err)
	}
}

//note certain what these are
var rawSDPrefixTemplate = []byte{0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func run(sidStr string) error {
	var sidBytes []byte

	//1-byte revision
	sidBytes = append(sidBytes, 0x01)

	sidParts := strings.Split(sidStr, "-")

	//1-byte subauthority count
	subAuthorityCount := len(sidParts[3:])
	sidBytes = append(sidBytes, byte(subAuthorityCount))

	//6-byte authority field (big-endian)
	authorityBytes := make([]byte, 6)
	authorityInt, err := strconv.Atoi(sidParts[2])
	if err != nil {
		return err
	}

	//write 32bit int to the last 32 bits (offset 2-bytes)
	binary.BigEndian.PutUint32(authorityBytes[2:], uint32(authorityInt))

	sidBytes = append(sidBytes, authorityBytes...)

	//4-byte subauthority fields (little-endian)
	for _, subAuthorityPart := range sidParts[3:] {
		subAuthorityBytes := make([]byte, 4)

		subAuthorityInt, err := strconv.Atoi(subAuthorityPart)
		if err != nil {
			return err
		}

		//write 32bit int
		binary.LittleEndian.PutUint32(subAuthorityBytes, uint32(subAuthorityInt))

		sidBytes = append(sidBytes, subAuthorityBytes...)
	}

	rawSDHeader := rawSDPrefixTemplate

	//group offset position
	rawSDHeader[12] = byte(len(sidBytes))

	//compose into O:<SID>:G<SID> equivalent
	rawSDBytes := append(rawSDHeader, append(sidBytes, sidBytes...)...)

	rawSDBase64 := base64.StdEncoding.EncodeToString(rawSDBytes)
	fmt.Println(rawSDBase64)

	return nil
}
