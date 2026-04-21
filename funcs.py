SIGNATURES = [
  
    {
        "name": "PowerShell Execution",
        "pattern": b"powershell",
        "severity": "MEDIUM",
        "category": "execution"
    },
    {
        "name": "CMD Execution",
        "pattern": b"cmd /c",
        "severity": "MEDIUM",
        "category": "execution"
    },

  
    {
        "name": "PowerShell Web Download",
        "pattern": b"Invoke-WebRequest",
        "severity": "MEDIUM",
        "category": "download"
    },
    {
        "name": "WebClient DownloadString",
        "pattern": b"DownloadString",
        "severity": "MEDIUM",
        "category": "download"
    },

 
    {
        "name": "WMI Process Creation",
        "pattern": b"wmic process call create",
        "severity": "HIGH",
        "category": "lolbin"
    },

   
    {
        "name": "Encoded PowerShell Command",
        "pattern": b"-EncodedCommand",
        "severity": "HIGH",
        "category": "obfuscation"
    },
    {
        "name": "Base64 Decode Usage",
        "pattern": b"FromBase64String",
        "severity": "HIGH",
        "category": "obfuscation"
    }
]

def sig_to_sting(sigs):
    output_string=""
    for sig in sigs:
        name=sig["name"]
        cat=sig["category"]
        severity=sig["severity"]
        output_string+=f"{name}| category:{cat} |Severity:{severity}\n\n"
    return output_string
def sig_check(file):
    matches=[]
    with open(file, "rb") as f:
        data = f.read()
    for sig in SIGNATURES:
        if sig["pattern"] in data:
            matches.append(sig)
    
    if len(matches)==0:
        return "nothing found"
    else:
        return sig_to_sting(matches)