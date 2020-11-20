# SID to rawsd

Demonstrates converting an SID into security descriptor suitable for tar.PAXRecords["MSWINDOWS.rawsd"] in [Windows OCI image layers](https://github.com/opencontainers/image-spec/blob/master/layer.md#:~:text=MSWINDOWS.rawsd).

Generated rawsd is equivalent to the SDDL `O:<SID>G:<SID>` 

Powershell Equivalent:
```powershell
$sid = "S-1-5-32-544"
$sddlValue = "O:"+$sid+"G:"+$sid
$sddl = (ConvertFrom-SddlString $sddlValue)
$sddlBytes = [byte[]]::New($sddl.RawDescriptor.BinaryLength)
$sddl.RawDescriptor.GetBinaryForm($sddlBytes, 0)
[Convert]::ToBase64String($sddlBytes)
# Output: AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAgAgAAAQIAAAAAAAUgAAAAIAIAAA==
```

## Usage
```
go run main.go S-1-5-32-544 S-1-5-32-544
# Output: AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAgAgAAAQIAAAAAAAUgAAAAIAIAAA==
```

## References:

* http://www.adamretter.org.uk/blog/entries/active-directory-ldap-users-primary-group.xml
* https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs




## Testdata
```
"O:S-1-5-32-545G:S-1-5-32-545" (aka "O:BUG:BU") 
$  echo AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAgAgAAAQIAAAAAAAUgAAAAIAIAAA== | base64 -d | hexdump
0000000 01 00 00 80 14 00 00 00 24 00 00 00 00 00 00 00
0000010 00 00 00 00 01 02 00 00 00 00 00 05 20 00 00 00
0000020 20 02 00 00 01 02 00 00 00 00 00 05 20 00 00 00
0000030 20 02 00 00
0000034

"O:S-1-5-32-544G:S-1-5-32-544" (aka "O:BAG:BA") 
$  echo AQAAgBQAAAAkAAAAAAAAAAAAAAABAgAAAAAABSAAAAAgAgAAAQIAAAAAAAUgAAAAIAIAAA== | base64 -d | hexdump
0000000 01 00 00 80 14 00 00 00 24 00 00 00 00 00 00 00
0000010 00 00 00 00 01 02 00 00 00 00 00 05 20 00 00 00
0000020 20 02 00 00 01 02 00 00 00 00 00 05 20 00 00 00
0000030 20 02 00 00
0000034

"O:S-1-5-93-2-1G:S-1-5-93-2-1" (aka ContainerUser/ContainerUser)
$  echo AQAAgBQAAAAoAAAAAAAAAAAAAAABAwAAAAAABV0AAAACAAAAAQAAAAEDAAAAAAAFXQAAAAIAAAABAAAA | base64 -d | hexdump
0000000 01 00 00 80 14 00 00 00 28 00 00 00 00 00 00 00
0000010 00 00 00 00 01 03 00 00 00 00 00 05 5d 00 00 00
0000020 02 00 00 00 01 00 00 00 01 03 00 00 00 00 00 05
0000030 5d 00 00 00 02 00 00 00 01 00 00 00
000003c

whoami /user
"O:S-1-5-21-2479766889-1967700041-1834931371-1000G:S-1-5-21-2479766889-1967700041-1834931371-1000"
$  echo AQAAgBQAAAAwAAAAAAAAAAAAAAABBQAAAAAABRUAAABpPc6TSbhIdavUXm3oAwAAAQUAAAAAAAUVAAAAaT3Ok0m4SHWr1F5t6AMAAA== | base64 -d | hexdump
0000000 01 00 00 80 14 00 00 00 30 00 00 00 00 00 00 00
0000010 00 00 00 00 01 05 00 00 00 00 00 05 15 00 00 00
0000020 69 3d ce 93 49 b8 48 75 ab d4 5e 6d e8 03 00 00
0000030 01 05 00 00 00 00 00 05 15 00 00 00 69 3d ce 93
0000040 49 b8 48 75 ab d4 5e 6d e8 03 00 00
000004c
```
