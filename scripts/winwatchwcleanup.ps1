#Get Parameters
param (
    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
    [String]$WatchmakerParam,

    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
    [String]$WatchmakerParam2
)

#Install Updates
. { iwr -useb http://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force
Enable-MicrosoftUpdate
Install-WindowsUpdate -SuppressReboots -AcceptEula

#open IE to initialize cert
#$ie = new-object -com "InternetExplorer.Application"
#$ie.navigate("http://s3.amazonaws.com/app-chemistry/files/")

#$BootstrapUrl = "https://raw.githubusercontent.com/ewierschke/watchmaker/bootstrap/docs/files/bootstrap/watchmaker-bootstrap.ps1"
$BootstrapUrl = "https://raw.githubusercontent.com/plus3it/watchmaker/master/docs/files/bootstrap/watchmaker-bootstrap.ps1"
$PythonUrl = "https://www.python.org/ftp/python/3.6.4/python-3.6.4-amd64.exe"
$PypiUrl = "https://pypi.org/simple"

# Download bootstrap file
$BootstrapFile = "${Env:Temp}\$(${BootstrapUrl}.split('/')[-1])"
(New-Object System.Net.WebClient).DownloadFile("$BootstrapUrl", "$BootstrapFile")

# Install python
& "$BootstrapFile" -PythonUrl "$PythonUrl" -Verbose -ErrorAction Stop

# Install watchmaker
#pip install --build "${Env:Temp}" --index-url="$PypiUrl" --upgrade pip setuptools watchmaker
python -m pip install --index-url="$PypiUrl" --upgrade pip<10 setuptools
pip install --build "${Env:Temp}" --index-url="$PypiUrl" --upgrade watchmaker

# Run watchmaker
watchmaker --no-reboot --log-level debug --log-dir=C:\Watchmaker\Logs ${WatchmakerParam} ${WatchmakerParam2} --config="C:\Program Files\Python36\Lib\site-packages\watchmaker\static\config.yaml"

if ($? -ne 'True') {
    $logfilepath = "${env:windir}\Temp\winwatchwcleanup-log.log"
    $text = "Watchmaker failed to run: $(Get-Date)"
    $text | Out-File -Encoding ASCII -Append -FilePath $logfilepath
    Start-Sleep -s 60
} else {
    $logfilepath = "${env:windir}\Temp\winwatchwcleanup-log.log"
    $text = "Watchmaker succeeded: $(Get-Date)"
    $text | Out-File -Encoding ASCII -Append -FilePath $logfilepath
    # Remove previous scheduled task
    $taskName = "RunNextScript";
    $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
    if ($taskExists) {
        Unregister-ScheduledTask -TaskName ${taskName} -Confirm:$false;
    }
    #removing webrole installed earlier for custom wam
    $webroleinstalled = (Get-WindowsFeature | Where-Object {$_.Installed -eq $true -and $_.FeatureType -eq 'Role'} | Where-Object {$_.Name -Like "*Web-Server*"})
    if ($webroleinstalled) {
        Uninstall-WindowsFeature -Name Web-Server
    }
}

gpupdate /force

powershell.exe "Restart-Computer -Force -Verbose";
