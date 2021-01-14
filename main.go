package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"sid-to-rawsd/accesscontrol"
)

func main() {
	ownerSidPtr := flag.String("owner-sid", "", "owner SID string")
	groupSidPtr := flag.String("group-sid", "", "group SID string")
	flag.Parse()
	if *ownerSidPtr == "" || *groupSidPtr == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*ownerSidPtr, *groupSidPtr); err != nil {
		panic(err)
	}
}

func run(ownerSIDStr, groupSIDStr string) error {
	ownerSID, err := accesscontrol.StringToSid(ownerSIDStr)
	if err != nil {
		return err
	}

	groupSID, err := accesscontrol.StringToSid(groupSIDStr)
	if err != nil {
		return err
	}

	securityDescriptor := accesscontrol.NewSecurityDescriptor()

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
