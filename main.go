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

func run(ownerSIDStr, groupSIDStr string) error {
	ownerSID, err := StringToSid(ownerSIDStr)
	if err != nil {
		return err
	}

	groupSID, err := StringToSid(groupSIDStr)
	if err != nil {
		return err
	}

	securityDescriptor := NewSecurityDescriptor()

	securityDescriptor.SetOwner(ownerSID)
	securityDescriptor.SetGroup(groupSID)

	rawSDBytes, err := securityDescriptor.Bytes()
	if err != nil {
		return err
	}

	rawSDBase64 := base64.StdEncoding.EncodeToString(rawSDBytes)
	fmt.Println(rawSDBase64)

	return nil
}

func NewSecurityDescriptor() *SECURITY_DESCRIPTOR {
	return &SECURITY_DESCRIPTOR{
		revision: 0x1,
		sbz1:     0x0,    //ignore rm control case
		control:  0x8000, //Self-relative only
		owner:    nil,
		group:    nil,
		sacl:     nil,
		dacl:     nil,
	}
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
type SID struct {
	revision          byte
	subAuthorityCount uint8
	authority         uint32
	subAuthorities    []uint32
}

type ACL struct {
	aclRevision byte
	sbz1        byte
	aclSize     uint16
	aceCount    uint16
	sbz2        uint16
}

func (a *ACL) Bytes() []byte {
	return nil // not implemented
}

// Data structure: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
// Windows implementation: https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs
type SECURITY_DESCRIPTOR struct {
	revision uint8
	sbz1     byte
	control  uint16
	owner    *SID
	group    *SID
	sacl     *ACL
	dacl     *ACL
}

// This is a subset impl of: https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs#L261
func (sd *SECURITY_DESCRIPTOR) Bytes() ([]byte, error) {
	var sdBytes []byte

	//1-byte revision
	sdBytes = append(sdBytes, sd.revision)

	//1-byte sbz1
	sdBytes = append(sdBytes, sd.sbz1)

	//2-byte Control
	controlBytes := make([]byte, 2)

	//write 32bit int to the control bytes
	binary.LittleEndian.PutUint16(controlBytes[:], sd.control)

	sdBytes = append(sdBytes, controlBytes...)

	fmt.Printf("len %d\n", len(sdBytes))

	//4-byte offset section (4 total)
	offsetEntryBytes := make([]byte, 16)

	var ownerOffset uint32 = 0x0
	if sd.owner != nil {
		// owner will be written after sdBytes + offsetEntryBytes
		ownerOffset = uint32(len(sdBytes) + len(offsetEntryBytes))
	}

	//write 32bit uint to the control bytes
	binary.LittleEndian.PutUint32(offsetEntryBytes[0:], ownerOffset)

	//4-byte group offset
	var groupOffset uint32 = 0x0
	if sd.group != nil {
		// group will be written after sdBytes + offsetEntryBytes + owner.Bytes
		groupOffset = ownerOffset + uint32(len(sd.owner.Bytes()))
	}

	//write 32bit uint to the control bytes
	binary.LittleEndian.PutUint32(offsetEntryBytes[4:], groupOffset)

	//4-byte sacl offset
	var saclOffset uint32 = 0x0
	if sd.sacl != nil {
		// sacl will be written after sdBytes + offsetEntryBytes + owner.Bytes + group.Bytes
		saclOffset = groupOffset + uint32(len(sd.group.Bytes()))
	}

	//write 32bit uint to the control bytes
	binary.LittleEndian.PutUint32(offsetEntryBytes[8:], saclOffset)

	//4-byte sacl offset
	var daclOffset uint32 = 0x0
	if sd.dacl != nil {
		// sacl will be written after sdBytes + offsetEntryBytes + owner.Bytes + group.Bytes
		daclOffset = saclOffset + uint32(len(sd.sacl.Bytes()))
	}

	//write 32bit uint to the control bytes
	binary.LittleEndian.PutUint32(offsetEntryBytes[12:], daclOffset)

	sdBytes = append(sdBytes, offsetEntryBytes...)

	// append SID and ACL bytes
	sdBytes = append(sdBytes, sd.owner.Bytes()...)
	sdBytes = append(sdBytes, sd.group.Bytes()...)
	sdBytes = append(sdBytes, sd.sacl.Bytes()...)
	sdBytes = append(sdBytes, sd.dacl.Bytes()...)

	return sdBytes, nil
}

func (sd *SECURITY_DESCRIPTOR) SetOwner(sid *SID) {
	sd.owner = sid
}

func (sd *SECURITY_DESCRIPTOR) SetGroup(sid *SID) {
	sd.group = sid
}

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
