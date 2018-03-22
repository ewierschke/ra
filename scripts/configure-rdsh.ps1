# Define System variables
$ConfigureRDSHDir = "${env:SystemDrive}\buildscripts\3-ConfigureRDSH"
$ConfigureRDSHLogDir = "${ConfigureRDSHDir}\Logs"
$LogSource = "ConfigureRDSH"
$DateTime = $(get-date -format "yyyyMMdd_HHmm_ss")
$ConfigureRDSHLogFile = "${ConfigureRDSHLogDir}\ConfigureRDSH-log_${DateTime}.txt"
$ScriptName = $MyInvocation.mycommand.name
$ErrorActionPreference = "Stop"
$credspath = "${env:SystemDrive}\buildscripts"
$nextscript = "winwatchwcleanup"

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
        md $key -verbose -force
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
# Create the ConfigureRDSH log directory
New-Item -Path $ConfigureRDSHDir -ItemType "directory" -Force 2>&1 > $null
New-Item -Path $ConfigureRDSHLogDir -ItemType "directory" -Force 2>&1 > $null
# Increase the screen width to avoid line wraps in the log file
Set-OutputBuffer -Width 10000
# Start a transcript to record script output
Start-Transcript $ConfigureRDSHLogFile

# Create a "ConfigureRDSH" event log source
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
Invoke-Webrequest "https://raw.githubusercontent.com/ewierschke/armtemplates/runwincustdata/scripts/${nextscript}.ps1" -Outfile "${ConfigureRDSHDir}\${nextscript}.ps1";

# Do the work
#[CmdLetBinding()]
#Param(
#    $ServerFQDN,
#    $DomainNetBiosName,
#    $GroupName
#    )

#Based on:
# * https://s3.amazonaws.com/app-chemistry/scripts/configure-rdsh.ps1

if (-not $ServerFQDN)
{
    try
    {
        $json = invoke-restmethod -Headers @{"Metadata"="true"} -uri http://169.254.169.254/metadata/instance?api-version=2017-04-02
        $name = $json.compute.name
    }
    catch
    {
        if (-not $name)
        {
            $name = [System.Net.DNS]::GetHostByName('').HostName
        }
    }
    $ServerFQDN = $name
}

# Add Windows features
$null = Install-WindowsFeature @(
    "RDS-RD-Server"
    "RDS-Licensing"
    "Search-Service"
    "Desktop-Experience"
    "RSAT-ADDS-Tools"
    "GPMC"
)
$null = Import-Module RemoteDesktop,RemoteDesktopServices

# Configure RDS Licensing
Set-Item -path RDS:\LicenseServer\Configuration\Firstname -value "End" -Force
Set-Item -path RDS:\LicenseServer\Configuration\Lastname -value "User" -Force
Set-Item -path RDS:\LicenseServer\Configuration\Company -value "Company" -Force
Set-Item -path RDS:\LicenseServer\Configuration\CountryRegion -value "United States" -Force
$ActivationStatus = Get-Item -Path RDS:\LicenseServer\ActivationStatus
if ($ActivationStatus.CurrentValue -eq 0)
{
    Set-Item -Path RDS:\LicenseServer\ActivationStatus -Value 1 -ConnectionMethod AUTO -Reason 5 -ErrorAction Stop
}
$obj = gwmi -namespace "Root/CIMV2/TerminalServices" Win32_TerminalServiceSetting
$null = $obj.SetSpecifiedLicenseServerList("localhost")
$null = $obj.ChangeMode(2)

# Grant remote access privileges to domain group
if ($DomainNetBiosName -and $GroupName)
{
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group"
    $groupmembers = @(@($group.Invoke("Members")) | `
        foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)})

    if ($groupmembers -notcontains $GroupName)
    {
        $group.Add("WinNT://$DomainNetBiosName/$GroupName,group")
    }
}

# Configure DNS registration
$adapters = get-wmiobject -class Win32_NetworkAdapterConfiguration -filter "IPEnabled=TRUE"
$null = $adapters | foreach-object { $_.SetDynamicDNSRegistration($TRUE, $TRUE) }

# Enable SmartScreen
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -ErrorAction Stop -Value "RequireAdmin" -Force

# Set the Audio Service to start automatically, without failing if the service name cannot be found
@(Get-Service -Name "audiosrv" -ErrorAction SilentlyContinue) | % { Set-Service -Name $_.Name -StartupType "Automatic" }

# Create public desktop shortcut for Windows Security
$WindowsSecurityPath = "${env:SYSTEMDRIVE}\Users\Public\Desktop\Windows Security.lnk"
$WindowsSecurityShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("${WindowsSecurityPath}")
$WindowsSecurityShortcut.TargetPath = "Powershell"
$WindowsSecurityShortcut.Arguments = '-noprofile -nologo -noninteractive -command "(new-object -ComObject shell.application).WindowsSecurity()"'
$WindowsSecurityShortcut.Description = "Windows Security"
$WindowsSecurityShortcut.IconLocation = "${env:SYSTEMROOT}\System32\imageres.dll,1"
$WindowsSecurityShortcut.Save()

# Create public desktop shortcut for Sign Out
$SignoffPath = "${env:SYSTEMDRIVE}\Users\Public\Desktop\Sign Out.lnk"
$SignOffShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("${SignoffPath}")
$SignOffShortcut.TargetPath = "logoff.exe"
$SignOffShortcut.Description = "Sign Out"
$SignOffShortcut.IconLocation = "${env:SYSTEMROOT}\System32\imageres.dll,81"
$SignOffShortcut.Save()

# Install Git for Windows
#$GitUrl = "https://github.com/git-for-windows/git/releases/download/v2.11.0.windows.1/Git-2.11.0-64-bit.exe"
#$GitInstaller = "${Env:Temp}\Git-2.11.0-64-bit.exe"
#(new-object net.webclient).DownloadFile("${GitUrl}","${GitInstaller}")
#$GitParams = "/SILENT /NOCANCEL /NORESTART /SAVEINF=${Env:Temp}\git_params.txt"
#$null = Start-Process -FilePath ${GitInstaller} -ArgumentList ${GitParams} -PassThru -Wait

# Install PsGet, a PowerShell Module
#(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex

#Install updates
#. { iwr -useb http://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force
#Enable-MicrosoftUpdate
#Install-WindowsUpdate -SuppressReboots -AcceptEula

# Remove previous scheduled task
log -LogTag ${ScriptName} "UnRegistering previous scheduled task"
Unregister-ScheduledTask -TaskName "RunNextScript" -Confirm:$false;

#Create an atlogon scheduled task to run next script
log -LogTag ${ScriptName} "Registering a scheduled task at startup to run the next script"
$msg = "Please upgrade Powershell and try again."

$taskname = "RunNextScript"
if ($PSVersionTable.psversion.major -ge 4) {
    $A = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass $ConfigureRDSHDir\${nextscript}.ps1"
    $T = New-ScheduledTaskTrigger -AtStartup
    $P = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel "Highest" -LogonType "ServiceAccount"
    $S = New-ScheduledTaskSettingsSet
    $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
    Register-ScheduledTask -TaskName $taskname -InputObject $D 2>&1 | log -LogTag ${ScriptName}
} else {
    invoke-expression "& $env:systemroot\system32\schtasks.exe /create /SC ONLOGON /RL HIGHEST /NP /V1 /RU SYSTEM /F /TR `"msg * /SERVER:%computername% ${msg}`" /TN `"${taskname}`"" 2>&1 | log -LogTag ${ScriptName}
}

# Check for existence of creds files and adjust scheduled task to run as supplied credentials (holdover from old approach)
$testPath = "${credspath}\lcladminname.txt";
if (Test-Path $testPath -PathType Leaf) {
    $Computer = $env:COMPUTERNAME;
    $UsernameFilePath = "${credspath}\lcladminname.txt";
    $Username = Get-Content $UsernameFilePath;
    $LclAdminCredsFilePath = "${credspath}\lcladminpass.txt";
    $LclAdminKeyFilePath = "${credspath}\lcladminkey.txt";
    $LclAdminKey = Get-Content $LclAdminKeyFilePath;
    $LclAdminPass = Get-Content $LclAdminCredsFilePath;
    $SecPassword = $LclAdminPass | ConvertTo-SecureString -Key $LclAdminKey;
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPassword);
    $adminpass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR);
    Set-ScheduledTask -User "$Computer\$Username" -Password $adminpass -TaskName $taskname;
    #todo-add test for failure... if failure disable task, only remove-items if success
    log -LogTag ${ScriptName} "deleting creds"
    Remove-Item "${credspath}\lcladminpass.txt" -Force -Recurse;
    Remove-Item "${credspath}\lcladminkey.txt" -Force -Recurse;
    Remove-Item "${credspath}\lcladminname.txt" -Force -Recurse;
}

log -LogTag ${ScriptName} "Rebooting"
powershell.exe "Restart-Computer -Force -Verbose";