rule Suspicious_PowerShell_Encoded
{
    meta:
        severity = "HIGH"
        description = "Detects encoded PowerShell execution"

    strings:
        $ps = "powershell"
        $enc = "-EncodedCommand"

    condition:
        $ps and $enc
}


rule PowerShell_DownloadString
{
    meta:
        severity = "HIGH"
        description = "Detects PowerShell DownloadString usage"

    strings:
        $dl = "DownloadString"

    condition:
        $dl
}


rule WMI_Process_Creation
{
    meta:
        severity = "HIGH"
        description = "Detects WMI-based process creation"

    strings:
        $wmi = "wmic process call create"

    condition:
        $wmi
}


rule CMD_PowerShell_Chain
{
    meta:
        severity = "MEDIUM"
        description = "Detects CMD launching PowerShell"

    strings:
        $cmd = "cmd /c"
        $ps = "powershell"

    condition:
        $cmd and $ps
}


rule Base64_Decode_Usage
{
    meta:
        severity = "MEDIUM"
        description = "Detects Base64 decoding functions"

    strings:
        $b64 = "FromBase64String"

    condition:
        $b64
}