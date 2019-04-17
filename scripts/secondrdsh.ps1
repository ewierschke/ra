# Define System variables
$SecondRDSHDir = "${env:SystemDrive}\buildscripts\2-SecondRDSH"
$SecondRDSHLogDir = "${SecondRDSHDir}\Logs"
$LogSource = "SecondRDSH"
$DateTime = $(get-date -format "yyyyMMdd_HHmm_ss")
$SecondRDSHLogFile = "${SecondRDSHLogDir}\SecondRDSH-log_${DateTime}.txt"
$ScriptName = $MyInvocation.mycommand.name
$ErrorActionPreference = "Stop"
$nextscript = "configure-rdsh"
$scriptsource = "https://raw.githubusercontent.com/ewierschke/ra/wip/scripts/"
$getscript = "${scriptsource}${nextscript}.ps1"

# Define Functions
function log {
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0,ValueFromPipeLine=$true)] [string[]]
        $LogMessage,
        [Parameter(Mandatory=$false,Position=1)] [string]
        $EntryType="Information",
        [Parameter(Mandatory=$false,Position=2)] [string]
        $LogTag="${ScriptName}"
    )
    PROCESS {
        foreach ($message in $LogMessage) {
            $date = get-date -format "yyyyMMdd.HHmm.ss"
            Manage-Output -EntryType $EntryType "${date}: ${LogTag}: $message"
        }
    }
}

function die($Msg) {
    log -EntryType "Error" -LogMessage $Msg; Stop-Transcript; throw
}

function Manage-Output {
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0,ValueFromPipeLine=$true)] [string[]]
        $Output,
        [Parameter(Mandatory=$false,Position=1)] [string]
        $EntryType="Information"
    )
    PROCESS {
        foreach ($str in $Output) {
            #Write to the event log
            Write-EventLog -LogName Application -Source "${LogSource}" -EventId 1 -EntryType $EntryType -Message "${str}"
            #Write to the default stream (this way we don't clobber the output stream, and the output will be captured by Start-Transcript)
            "${str}" | Out-Default
        }
    }
}

function Set-RegistryValue($Key,$Name,$Value,$Type=[Microsoft.win32.registryvaluekind]::DWord) {
    $Parent=split-path $Key -parent
    $Parent=get-item $Parent
    $Key=get-item $Key
    $Keyh=$Parent.opensubkey($Key.name.split("\")[-1],$true)
    $Keyh.setvalue($Name,$Value,$Type)
    $Keyh.close()
}

function Set-OutputBuffer($Width=10000) {
    $keys=("hkcu:\console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe",
           "hkcu:\console\%SystemRoot%_SysWOW64_WindowsPowerShell_v1.0_powershell.exe")
    # other titles are ignored
    foreach ($key in $keys) {
        mkdir $key -verbose -force
        Set-RegistryValue $key FontSize 0x00050000
        Set-RegistryValue $key ScreenBufferSize 0x02000200
        Set-RegistryValue $key WindowSize 0x00200200
        Set-RegistryValue $key FontFamily 0x00000036
        Set-RegistryValue $key FontWeight 0x00000190
        Set-ItemProperty $key FaceName "Lucida Console"

        $bufferSize=$host.ui.rawui.bufferSize
        $bufferSize.width=$Width
        $host.ui.rawui.BufferSize=$BufferSize
        $maxSize=$host.ui.rawui.MaxWindowSize
        $windowSize=$host.ui.rawui.WindowSize
        $windowSize.width=$maxSize.width
        $host.ui.rawui.WindowSize=$windowSize
    }
}

# Begin Script
# Create the SecondRDSH log directory
New-Item -Path $SecondRDSHDir -ItemType "directory" -Force 2>&1 > $null
New-Item -Path $SecondRDSHLogDir -ItemType "directory" -Force 2>&1 > $null
$OSver = (Get-CimInstance Win32_OperatingSystem).version
if ($OSver -lt 10)
{
     # Increase the screen width to avoid line wraps in the log file
     Set-OutputBuffer -Width 10000
}
# Start a transcript to record script output
Start-Transcript $SecondRDSHLogFile

# Create a "SecondRDSH" event log source
try {
    New-EventLog -LogName Application -Source "${LogSource}"
} catch {
    if ($_.Exception.GetType().FullName -eq "System.InvalidOperationException") {
        # Event log already exists, log a message but don't force an exit
        log "Event log source, ${LogSource}, already exists. Continuing..."
    } else {
        # Unhandled exception, log an error and exit!
        "$(get-date -format "yyyyMMdd.HHmm.ss"): ${ScriptName}: ERROR: Encountered a problem creating the event log source." | Out-Default
        Stop-Transcript
        throw
    }
}

# Get the next script
log -LogTag ${ScriptName} "Downloading ${nextscript}.ps1"
Invoke-Webrequest "${getscript}" -Outfile "${SecondRDSHDir}\${nextscript}.ps1";

# Do the work
$OSver = (Get-CimInstance Win32_OperatingSystem).version
#Server 2012 R2
if ($OSver -lt 10)
{

     # Add Windows features
     $null = Install-WindowsFeature @(
         "RDS-RD-Server"
         "RDS-Licensing"
         "Search-Service"
         "Desktop-Experience"
         "RSAT-ADDS-Tools"
         "GPMC"
     )
}
#Server 2016+
if ($OSver -gt 10)
{
    $RequiredFeatures = @(
        "RDS-RD-Server"
        "RDS-Licensing"
    )
    
    $ExtraFeatures = @(
      "Search-Service"
      "RSAT-ADDS-Tools"
      "GPMC"
    )
    
    $MissingFeatures = @()
    foreach ($Feature in (Get-WindowsFeature $RequiredFeatures))
    {
        if (-not $Feature.Installed)
        {
            $MissingFeatures += $Feature.Name
        }
    }
    if ($MissingFeatures)
    {
        throw "Missing required Windows features: $($MissingFeatures -join ',')"
    }
    
    # Validate availability of RDS Licensing configuration
    $null = Import-Module RemoteDesktop,RemoteDesktopServices -Verbose:$false
    $TestPath = "RDS:\LicenseServer"
    if (-not (Get-ChildItem $TestPath -ErrorAction SilentlyContinue))
    {
        throw "System needs to reboot to create the path: ${TestPath}"
    }
    
    # # Get the system name
    #$SystemName = [System.Net.DNS]::GetHostByName('').HostName
    
    # Install extra Windows features
    if ($ExtraFeatures)
    {
        Install-WindowsFeature $ExtraFeatures
    }
    
    #$RequiredRoles = @(
    #    "RDS-RD-SERVER"
    #)
}

# Remove previous scheduled task (if it exists)
log -LogTag ${ScriptName} "Unregistering previous scheduled task"
$taskName = "RunNextScript";
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
if ($taskExists) {
    Unregister-ScheduledTask -TaskName ${taskName} -Confirm:$false;
}

#Create an atlogon scheduled task to run next script
log -LogTag ${ScriptName} "Registering a scheduled task at startup to run the next script"
$msg = "Please upgrade Powershell and try again."

$taskname = "RunNextScript"
if ($PSVersionTable.psversion.major -ge 4) {
    $A = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass ${SecondRDSHDir}\${nextscript}.ps1"
    $T = New-ScheduledTaskTrigger -AtStartup
    $P = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel "Highest" -LogonType "ServiceAccount"
    $S = New-ScheduledTaskSettingsSet
    $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
    Register-ScheduledTask -TaskName $taskname -InputObject $D 2>&1 | log -LogTag ${ScriptName}
} else {
    invoke-expression "& $env:systemroot\system32\schtasks.exe /create /SC ONLOGON /RL HIGHEST /NP /V1 /RU SYSTEM /F /TR `"msg * /SERVER:%computername% ${msg}`" /TN `"${taskname}`"" 2>&1 | log -LogTag ${ScriptName}
}

log -LogTag ${ScriptName} "Rebooting"
powershell.exe "Restart-Computer -Force -Verbose";