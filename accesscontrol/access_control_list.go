package accesscontrol

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
