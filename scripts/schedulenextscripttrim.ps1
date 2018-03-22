# Set control file path to be used to prevent multiple executions via custom script extension
$ctrlfilepath = "${env:windir}\Temp\schedulenextscripttrim-control.log"

if ( -not (Test-Path $ctrlfilepath -PathType Leaf)) {
    # Log start time
    $text = "schedulenextscripttrim.ps1 started at: $(Get-Date)"
    $text | Out-File -Encoding ASCII -Append -FilePath $ctrlfilepath
    # Define System variables
    $ScheduleNextScriptDir = "${env:SystemDrive}\buildscripts\1-ScheduleNextScript"
    $nextscript = "firstrdsh"

    # Begin Script
    # Create the ScheduleNextScript log directory
    New-Item -Path $ScheduleNextScriptDir -ItemType "directory" -Force 2>&1 > $null

    # Get the next script
    $Stoploop = $false
    [int]$Retrycount = "0"
    do {
        try {
            Invoke-Webrequest "https://raw.githubusercontent.com/ewierschke/armtemplates/runwincustdata/scripts/${nextscript}.ps1" -Outfile "${ScheduleNextScriptDir}\${nextscript}.ps1";
            Write-Host "Downloaded next script"
            $Stoploop = $true
            }
        catch {
            if ($Retrycount -gt 3){
                Write-Host "Could not download next script after 3 retry attempts."
                $Stoploop = $true
                exit 1
            }
            else {
                Write-Host "Could not download next script retrying in 30 seconds..."
                Start-Sleep -Seconds 30
                $Retrycount = $Retrycount + 1
            }
        }
    }
    While ($Stoploop -eq $false)

    # Create an atlogon scheduled task to run next script
    $taskname = "RunNextScript"
    if ($PSVersionTable.psversion.major -ge 4) {
        $A = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass ${ScheduleNextScriptDir}\${nextscript}.ps1"
        $T = New-ScheduledTaskTrigger -AtStartup
        $P = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel "Highest" -LogonType "ServiceAccount"
        $S = New-ScheduledTaskSettingsSet
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
        Register-ScheduledTask -TaskName $taskname -InputObject $D 2>&1 
    } else {
        invoke-expression "& $env:systemroot\system32\schtasks.exe /create /SC ONLOGON /RL HIGHEST /NP /V1 /RU SYSTEM /F /TR `"msg * /SERVER:%computername% ${msg}`" /TN `"${taskname}`"" 2>&1
    }

    # Sleep 5min to allow other VM extensions to finish their installs
    Start-Sleep -s 300
    # Log completion time
    $text = "schedulenextscripttrim.ps1 ended with a reboot at: $(Get-Date)"
    $text | Out-File -Encoding ASCII -Append -FilePath $ctrlfilepath
    # Restart
    powershell.exe "Restart-Computer -Force -Verbose";
} else {
    $logfilepath = "${env:windir}\Temp\schedulenextscripttrim-log.log"
    $text = "schedulenextscripttrim.ps1 has already executed and attempted to execute again at: $(Get-Date)"
    $text | Out-File -Encoding ASCII -Append -FilePath $logfilepath
}