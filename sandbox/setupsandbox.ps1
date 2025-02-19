Set-ExecutionPolicy Bypass -Scope Process -Force;
Write-Host "Installing NuGet"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Write-Host "Installing Attack Lib"
Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-attacklib/master/install-attacklib.ps1'-UseBasicParsing);
Install-AttackLib -getAtomics -Force;
New-Item $PROFILE -Force;
Set-Variable -Name "ARTPath" -Value "C:\AttackLib"

Write-Output @"
Import-Module "$ARTPath/invoke-attacklib/Invoke-AttackLib.psd1" -Force;
`$PSDefaultParameterValues`["Invoke-AttackLibTest:PathToAtomicsFolder"] = "$ARTPath/atomics";
`$PSDefaultParameterValues`["Invoke-AttackLibTest:ExecutionLogPath"]="1.csv";
"@ > $PROFILE

. $PROFILE

Set-Location C:\AttackLib
