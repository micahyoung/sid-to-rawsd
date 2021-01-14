package accesscontrol

import (
	"encoding/binary"
	"fmt"
)

// Data structure: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
// Windows native implementation: https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs
type SECURITY_DESCRIPTOR struct {
	revision uint8
	sbz1     byte
	control  uint16
	owner    *SID
	group    *SID
	sacl     *ACL
	dacl     *ACL
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

func (sd *SECURITY_DESCRIPTOR) SetOwner(sid *SID) {
	sd.owner = sid
}

func (sd *SECURITY_DESCRIPTOR) SetGroup(sid *SID) {
	sd.group = sid
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
