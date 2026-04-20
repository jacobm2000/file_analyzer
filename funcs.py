SIGNATURES = [
    {
        "name": "Suspicious PowerShell",
        "pattern": b"powershell -enc",
        "severity": "HIGH"
    },
    {
        "name": "Command Execution",
        "pattern": b"cmd.exe",
        "severity": "MEDIUM"
    },
    {
        "name": "Download Cradle",
        "pattern": b"Invoke-WebRequest",
        "severity": "HIGH"
    },
    {
    "name": "Suspicious WMI Process Creation",
    
    "pattern": b"wmic process call create",
    
    "severity": "HIGH"
    },
    {
    "name": "PowerShell Remote Download (WebClient)",
    
    "pattern": b"DownloadString",
    
    "severity": "HIGH",
    
   
    },
    
    {
    "name": "EncodedCommand Usage",
    "pattern": b"-enc",
    "severity": "HIGH"
    },
    {
    "name": "Scripted Execution Chain (CMD → PowerShell)",
    "pattern": b"cmd /c",
    "severity": "MEDIUM"
    }
]

def sig_to_sting(sigs):
    output_string=""
    for sig in sigs:
        name=sig["name"]
        pattern=sig["pattern"]
        severity=sig["severity"]
        output_string+=f"{name}| Pattern:{pattern}| Severity:{severity}\n\n"
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