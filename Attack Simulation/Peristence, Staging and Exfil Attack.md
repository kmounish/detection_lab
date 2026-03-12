

## Suspicous Run Key created from PowerShell Script
- Persistence (TA0003)
  - Boot or Logon Autostart Execution (T1547)
    - Registry Run Keys / Startup Folder (T1547.001)

`event.dataset : "windows.sysmon_operational" and "*CurrentVersion\Run*" and event.action : "RegistryEvent (Value Set)" and registry.data.strings : (*.ps1 or *.bat)`

## Suspisous File written to Temp Directory
- Discovery (TA0007)
  - System Information Discovery (T1082)
  - Browser Information Discovery (T1217)

`event.dataset : ("windows.sysmon_operational" or "endpoint.events.file" ) and event.action: ("FileCreate" or "creation" or "overwrite" ) and "*C:\Windows\Temp\*" and file.name: (*History* or *.txt*)`


## Potential Exfiltartion with Archived files
- Collection (TA0009)
  - Data Staged (T1074)
    - Local Data Staging (T1074.001)

`event.dataset : ("windows.sysmon_operational" or "endpoint.events.file" ) and event.action: ("FileCreate" or "creation" or "overwrite" ) and "*C:\Windows\Temp\*" and file.name: (*.zip* or *.7z* or *.rar*)`

## Potential ZIP archive Exfiltration over FTP 

- Exfiltration (TA0010)
  - Automated Exfiltration (T1020)

`event.dataset: zeek.ftp and event.action: STOR and zeek.ftp.arg: *.zip`
