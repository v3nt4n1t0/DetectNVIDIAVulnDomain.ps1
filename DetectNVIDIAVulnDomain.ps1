﻿#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Author: Roberto Berrio (@v3nt4n1t0)
# Website: https://github.com/v3nt4n1t0
#
#
# Description: Script in PowerShell to detect vulnerable versions of NVIDIA Graphics Driver in a Windows domain. 
#
#
# CVEs: CVE‑2019‑5665 through CVE‑2019‑5671 and previous
# 
# 
# Considerations: 
#
# - Well configured WinRM on remote machines
# - Well configured firewall rules
# - Run the script with the Unrestricted or Bypass execution policies from Domain Controller
#
#
# Usage: 
#
# PS E:\Pruebas C# PowerShell> .\DetectNVIDIAVulnDomain.ps1
#
# PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectNVIDIAVulnDomain.ps1'
# 
################################################################################################################################################## 


$c = Get-ADComputer -Properties IPv4Address -Filter {Enabled -eq $true}
$cred = Get-Credential

echo ""
if($cred){
    foreach ($cname in $c.name ) {
    
        if(test-connection -ComputerName $cname -Count 1 -Quiet){
            try{
            $session = New-PSSession -ComputerName $cname -Credential $cred
            Invoke-Command -Session $session -ScriptBlock{
                $machine = (Get-WmiObject -class win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').ipaddress[0] + "," +[Environment]::GetEnvironmentVariable("ComputerName")
                $tipo=Get-WmiObject win32_VideoController -Property AdapterCompatibility

                if($tipo.AdapterCompatibility -like '*NVIDIA*') 
                {
                    $gpu=Get-WmiObject win32_VideoController -Property Caption
                    $gpuversion=Get-WmiObject win32_VideoController -Property DriverVersion
                    $version = $gpuversion.DriverVersion.Substring($gpuversion.DriverVersion.Length - 6, 6)
    
                    if($gpu.Caption -like '*Geforce*') {
                        if($version -lt 4.1917){Write-Host -ForegroundColor Red "$machine -> Vulnerable! Update drivers to version 419.17 o higher"}
                        else{"$machine -> No vulnerable"}
                    }
                    elseif(($gpu.Caption -like '*Quadro*') -or ($gpu.Caption -like '*NVS*')){
                        if($versionNVIDIA -lt 4.1917){Write-Host -ForegroundColor Red "$machine -> Vulnerable! Update drivers to version 419.17 o higher"}
                        else{"$machine -> No vulnerable"}
                    }
                    elseif($gpu.Caption -like '*Tesla*'){
                        if($versionNVIDIA -lt 4.1229){Write-Host -ForegroundColor Red "$machine -> Vulnerable! Update drivers to version 412.29 o higher"}
                        else{"$machine -> No vulnerable"}
                    }
                }
                else{ "$machine -> The machine does not have NVIDIA GPU or does not contain NVIDIA drivers"}

            }#ScriptBlock
    
            Remove-PSSession -Session $session

            }catch{ Write-Host -ForegroundColor Red -BackgroundColor Yellow "$cname is active, but the check can not be performed. Verify that the Administrator credentials are correct, that the remote computer has WinRM actived, or that Firewall rules are not blocking the connection"}
        }
        else{ Write-Host -ForegroundColor DarkYellow "$cname does not respond to ping or the machine is off. Check that firewall rules are not blocking the connection"}
    }#foreach
}
else{ Write-Host -ForegroundColor Red -BackgroundColor Yellow "Administrator credentials are required to run the script`n"}