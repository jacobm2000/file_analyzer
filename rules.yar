rule Suspicious_PowerShell_Encoded
{
    meta:
        severity = "HIGH"
        description = "encoded PowerShell execution"

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
        description = "PowerShell DownloadString usage"

    strings:
        $dl = "DownloadString"

    condition:
        $dl
}


rule WMI_Process_Creation
{
    meta:
        severity = "HIGH"
        description = "WMI-based process creation"

    strings:
        $wmi = "wmic process call create"

    condition:
        $wmi
}


rule CMD_PowerShell_Chain
{
    meta:
        severity = "MEDIUM"
        description = "CMD launching PowerShell"

    strings:
        $cmd = "cmd /c"
        $ps = "powershell"

    condition:
        $cmd and $ps
}

rule PowerShell_ExecutionPolicy_Bypass
{
    meta:
        severity = "HIGH"
        description = "PowerShell execution policy bypass"

    strings:
        $bypass = "ExecutionPolicy Bypass"

    condition:
        $bypass
}

rule Raw_IP_URL
{
    meta:
        severity = "MEDIUM"
        description = "Direct IP-based URL"

    strings:
        $ip = /http[s]?:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/

    condition:
        $ip
}

rule Base64_Decode_Usage
{
    meta:
        severity = "MEDIUM"
        description = "Base64 decoding functions"

    strings:
        $b64 = "FromBase64String"

    condition:
        $b64
}