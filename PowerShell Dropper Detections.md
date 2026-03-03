
# Attack: 
PowerShell dropper that checks enabled security features, system information, and creates a Microsoft Exclusion prior to downloading a remote payload that creates a reverse shell. 


# PowerShell Execution from Suspicious File
- MITRE ATT&CK (TA0002) Execution 
    - MITRE ATT&CK (T1059) Command and Scripting Interpreter
        - MITRE ATT&CK (T1059.001) PowerShell

Rule: `event.dataset : "windows.sysmon_operational" and process.command_line: *powershell* and process.parent.command_line : (*bat* or *src* or *png* or *pdf*) and process.parent.name: (*cmd* or *powershell*)`


# PowerShell downloading payloads with Invoke-WebRequest
- MITRE ATT&CK (TA0002) Execution 
    - MITRE ATT&CK (T1059) Command and Scripting Interpreter
        - MITRE ATT&CK (T1059.001) PowerShell

Rule: `event.dataset : "windows.sysmon_operational" and  (*Invoke-WebRequest*) and process.parent.name : *powershell*`


# PowerShell Command w/ Suspicious Arguments 
- MITRE ATT&CK (TA0002) Execution 
    - MITRE ATT&CK (T1059) Command and Scripting Interpreter
        - MITRE ATT&CK (T1059.001) PowerShell

Rule: `event.dataset : "windows.sysmon_operational" and message: ("*-w hidden*" and "*-nop*") and process.parent.name: *powershell*`


# Suspicous Exclusion made from PowerShell
- MITRE ATT&CK (TA0002) Execution 
    - MITRE ATT&CK (T1059) Command and Scripting Interpreter
        - MITRE ATT&CK (T1059.001) PowerShell

Rule: `event.dataset : "windows.sysmon_operational" and process.parent.name: *powershell* and message: "*Add-MpPreference -ExclusionPath*"`
