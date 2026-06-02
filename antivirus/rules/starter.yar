/*
   Starter YARA ruleset for the safe antivirus scanner.

   These are conservative, high-signal rules for common malware patterns. Drop
   additional .yar / .yara files in this directory (e.g. the free community sets
   from github.com/Yara-Rules/rules or Neo23x0/signature-base) to expand
   coverage -- they are loaded automatically.

   severity meta controls reporting: "malware" (default), "suspicious" (review),
   or "test". Rules here lean "suspicious" because they describe techniques that
   legitimate software occasionally uses too -- a human should confirm.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file (harmless)"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell that downloads and executes code in memory"
        severity = "suspicious"
        score = "50"
    strings:
        $iex = "Invoke-Expression" nocase
        $iex2 = "IEX" fullword nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Net.WebClient" nocase
        $enc = "-EncodedCommand" nocase
        $enc2 = "FromBase64String" nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        (any of ($iex*)) and (any of ($dl*) or any of ($enc*)) or
        ($hidden and any of ($dl*))
}

rule Suspicious_VBA_AutoExec_Shell
{
    meta:
        description = "Office VBA macro that auto-runs and spawns a shell/process"
        severity = "suspicious"
        score = "55"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Auto_Open" nocase
        $auto4 = "Workbook_Open" nocase
        $sh1 = "Shell" nocase
        $sh2 = "WScript.Shell" nocase
        $sh3 = "CreateObject" nocase
        $sh4 = "powershell" nocase
    condition:
        any of ($auto*) and any of ($sh*)
}

rule Suspicious_Windows_Persistence_RunKey
{
    meta:
        description = "References a Run registry key for autostart persistence"
        severity = "suspicious"
        score = "40"
    strings:
        $run1 = "\\CurrentVersion\\Run" nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg  = "reg add" nocase
        $regw = "RegSetValueEx" nocase
    condition:
        any of ($run*) and ($reg or $regw)
}

rule Suspicious_Embedded_PE_In_NonExe
{
    meta:
        description = "A second PE (MZ...This program) embedded inside a non-executable file"
        severity = "suspicious"
        score = "45"
    strings:
        $mz = "This program cannot be run in DOS mode"
    condition:
        // More than one embedded PE stub is a classic dropper/packer trait.
        #mz > 1 and filesize < 50MB
}
