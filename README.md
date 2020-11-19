# SID to rawsd

Demonstrates converting an SID into a rawsd for tar PAXRecords.

Generated rawsd is equivalent to the SDDL `O:<SID>G:<SID>` 

Powershell Equivalent:
```powershell
$sid = "S-1-5-32-544"
$sddlValue = "O:"+$sid+"G:"+$sid
$sddl = (ConvertFrom-SddlString $sddlValue)
$sddlBytes = [byte[]]::New($sddl.RawDescriptor.BinaryLength)
$sddl.RawDescriptor.GetBinaryForm($sddlBytes, 0)
[Convert]::ToBase64String($sddlBytes)
```
