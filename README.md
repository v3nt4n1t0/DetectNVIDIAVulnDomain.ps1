# NVIDIA Vulnerability Scanner for Domain

## Description: 

Script in PowerShell to detect vulnerable versions of NVIDIA Graphics Driver and GeForce Experience in a Windows domain. 

CVEs: CVE‑2019‑5702 and previous. 

### Considerations: 

- Well configured WinRM on remote machines.
- Well configured firewall rules. Allow ping to remote machines from the Domain Controller.
- Run the script with the Unrestricted or Bypass execution policies from Domain Controller.


## Usage: 

PS E:\Pruebas C# PowerShell> .\DetectNVIDIAVulnDomain.ps1

or

PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectNVIDIAVulnDomain.ps1'

or (Recommended: Save the following command and execute it whenever you want. You do not need to download the script. You will always run the most updated version of the script)

PS C:\prueba> iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/v3nt4n1t0/DetectNVIDIAVulnDomain.ps1/master/DetectNVIDIAVulnDomain.ps1")

You can try differents methods.

It will ask for the administrator credentials only once, and then, it will perform the checks.
