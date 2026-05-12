import math
import yara

SIGNATURES = [
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
    },
  
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
    }

 
   
]


def entropy_level(entropy):
      if entropy>=7.5:
        level="HIGH"
      elif(entropy>=6.5):
        level="MEDIUM"
      else:
        level="LOW"
      return level
def file_entropy(file_path: str, chunk_size=4096):
    byte_counts = [0] * 256
    total = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            total += len(chunk)
            for b in chunk:
                byte_counts[b] += 1

    if total == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy,2)

def sig_to_string(sigs):
    output_string=""
    for sig in sigs:
        name=sig["name"]
        cat=sig["category"]
        severity=sig["severity"]
        output_string+=f"{name}| category:{cat} |Severity:{severity}<br><br>"
    return output_string

def sig_check(file):
    matches=[]
    with open(file, "rb") as f:
        data = f.read()
    for sig in SIGNATURES:
        if sig["pattern"] in data:
            matches.append(sig)
    
    return matches
def yara_to_string(scan):
    output=""
    for entry in scan:
      
        name=entry['name']
        severity=entry['severity']
        description=entry['description']
        output+=f"{str(name)} | {str(severity)} | {str(description)} <br>"
    
    
    return output
def yara_check(file_path,rules):
    matches_found = []

    # Load YARA rules
    rules = yara.compile(rules)

    # Scan file
    matches = rules.match(file_path)

    # Convert matches into similar structure as sig_check
    for match in matches:
        matches_found.append({
            "name": match.rule,
            "severity": match.meta.get("severity", "UNKNOWN"),
            "description": match.meta.get(
                "description",
                "No description provided"
            ),
            "tags": match.tags
        })

    return matches_found