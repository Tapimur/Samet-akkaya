<#
.SYNOPSIS
    Windows acilisinda PowerShell penceresi acan kayitlari tarar.

.DESCRIPTION
    Registry Run, Startup klasorleri, Gorev Zamanlayici, WMI, servisler,
    PowerShell profil dosyalari ve logon komutlarini kontrol eder.
    Sadece okur; hicbir seyi silmez veya kapatmaz.

.EXAMPLE
    .\Find-PowerShellStartup.ps1
    Masaustune tarih damgali bir rapor yazar.
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)

$ErrorActionPreference = 'SilentlyContinue'
$hits = New-Object System.Collections.Generic.List[object]
$notes = New-Object System.Collections.Generic.List[string]

function Test-PsLike {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return $Text -match '(?i)powershell(?:\.exe)?|\bpwsh(?:\.exe)?|\.ps1\b|WindowsPowerShell|pwsh\.dll'
}

function Test-Suspicious {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return $Text -match '(?i)(-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|add-mppreference|exclusionpath|bypass|bitstransfer)'
}

function Add-Hit {
    param(
        [string]$Source,
        [string]$Name,
        [string]$Command,
        [string]$Extra = ''
    )
    $cmd = if ($null -eq $Command) { '' } else { [string]$Command }
    $hits.Add([pscustomobject]@{
        Source     = $Source
        Name       = $Name
        Command    = $cmd
        Suspicious = [bool](Test-Suspicious $cmd)
        Extra      = $Extra
    }) | Out-Null
}

function Get-RegValues {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path
    foreach ($name in $item.GetValueNames()) {
        $value = [string]$item.GetValue($name)
        if (Test-PsLike $name -or Test-PsLike $value) {
            Add-Hit -Source $Path -Name $name -Command $value
        }
    }
}

$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
)

foreach ($key in $runKeys) {
    Get-RegValues -Path $key
}

$startupFolders = @(
    [Environment]::GetFolderPath('Startup'),
    [Environment]::GetFolderPath('CommonStartup')
) | Where-Object { $_ }

foreach ($folder in $startupFolders) {
    if (-not (Test-Path -LiteralPath $folder)) { continue }
    Get-ChildItem -LiteralPath $folder -Force | ForEach-Object {
        $target = $_.FullName
        if ($_.Extension -match '(?i)\.lnk$') {
            try {
                $wsh = New-Object -ComObject WScript.Shell
                $shortcut = $wsh.CreateShortcut($_.FullName)
                $target = "$($shortcut.TargetPath) $($shortcut.Arguments)".Trim()
            } catch {
                $target = $_.FullName
            }
        }
        if (Test-PsLike $_.Name -or Test-PsLike $target) {
            Add-Hit -Source "Startup folder: $folder" -Name $_.Name -Command $target
        }
    }
}

try {
    Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $cmd = [string]$_.Command
        if (Test-PsLike $_.Name -or Test-PsLike $cmd) {
            Add-Hit -Source ("Win32_StartupCommand / " + $_.Location) -Name $_.Name -Command $cmd -Extra $_.User
        }
    }
} catch {
    $notes.Add('Win32_StartupCommand okunamadi.') | Out-Null
}

try {
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $actions = @($task.Actions | ForEach-Object {
            ('{0} {1}' -f $_.Execute, $_.Arguments).Trim()
        })
        $blob = ($actions + $task.TaskName + $task.TaskPath) -join ' '
        if (-not (Test-PsLike $blob)) { return }
        $triggers = @($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '
        Add-Hit -Source ("ScheduledTask " + $task.TaskPath) -Name $task.TaskName -Command ($actions -join ' | ') -Extra ("State=$($task.State); Triggers=$triggers")
    }
} catch {
    $notes.Add('Gorev Zamanlayici tam okunamadi. Scripti Yonetici olarak tekrar calistir.') | Out-Null
}

try {
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | ForEach-Object {
        if (Test-PsLike $_.Name -or Test-PsLike $_.Query) {
            Add-Hit -Source 'WMI EventFilter' -Name $_.Name -Command $_.Query
        }
    }
    Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object {
        $cmd = ('{0} {1}' -f $_.ExecutablePath, $_.CommandLineTemplate).Trim()
        if (Test-PsLike $cmd -or Test-PsLike $_.Name) {
            Add-Hit -Source 'WMI CommandLineEventConsumer' -Name $_.Name -Command $cmd
        }
    }
} catch {
    $notes.Add('WMI abonelikleri okunamadi (yonetici gerekebilir).') | Out-Null
}

$profilePaths = @(
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost,
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
    "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1"
) | Select-Object -Unique

foreach ($p in $profilePaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    if (Test-Path -LiteralPath $p) {
        $preview = (Get-Content -LiteralPath $p -TotalCount 20) -join ' / '
        Add-Hit -Source 'PowerShell profile' -Name $p -Command $preview
    }
}

try {
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($prop in @('Userinit', 'Shell', 'VmApplet')) {
        $val = [string]$winlogon.$prop
        if (Test-PsLike $val) {
            Add-Hit -Source 'Winlogon' -Name $prop -Command $val
        }
    }
} catch {
    $notes.Add('Winlogon anahtari okunamadi.') | Out-Null
}

try {
    Get-CimInstance Win32_Service | Where-Object {
        Test-PsLike $_.PathName -or Test-PsLike $_.Name
    } | ForEach-Object {
        Add-Hit -Source 'Service' -Name $_.Name -Command $_.PathName -Extra ("StartMode=$($_.StartMode); State=$($_.State)")
    }
} catch {
    $notes.Add('Servis listesi okunamadi.') | Out-Null
}

$recentPs = @()
try {
    $log = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 30
    $recentPs = $log | Select-Object -First 8 TimeCreated, Message
} catch {
    $notes.Add('PowerShell operational log okunamadi.') | Out-Null
}

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) {
        $desktop = $env:USERPROFILE
    }
    $OutputPath = Join-Path $desktop "powershell-startup-rapor-$stamp.txt"
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('=== PowerShell acilis tarama raporu ===')
[void]$sb.AppendLine(('Tarih     : {0}' -f (Get-Date)))
[void]$sb.AppendLine(('Bilgisayar: {0}' -f $env:COMPUTERNAME))
[void]$sb.AppendLine(('Kullanici : {0}' -f $env:USERNAME))
[void]$sb.AppendLine(('Yonetici  : {0}' -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
[void]$sb.AppendLine('')

if ($hits.Count -eq 0) {
    [void]$sb.AppendLine('PowerShell ile eslesen acilis kaydi bulunamadi.')
    [void]$sb.AppendLine('Pencere yine aciliyorsa Gorev Yoneticisi > Baslangic uygulamalari ve Autoruns (Microsoft) ile bak.')
} else {
    [void]$sb.AppendLine(('Bulunan kayit: {0}' -f $hits.Count))
    [void]$sb.AppendLine('')
    $i = 1
    foreach ($hit in $hits) {
        [void]$sb.AppendLine(('--- #{0} ---' -f $i))
        [void]$sb.AppendLine(('Kaynak    : {0}' -f $hit.Source))
        [void]$sb.AppendLine(('Ad        : {0}' -f $hit.Name))
        [void]$sb.AppendLine(('Komut     : {0}' -f $hit.Command))
        if ($hit.Extra) {
            [void]$sb.AppendLine(('Ek        : {0}' -f $hit.Extra))
        }
        [void]$sb.AppendLine(('Supheli   : {0}' -f $hit.Suspicious))
        [void]$sb.AppendLine('')
        $i++
    }
}

if ($notes.Count -gt 0) {
    [void]$sb.AppendLine('Notlar:')
    foreach ($n in $notes) { [void]$sb.AppendLine((' - {0}' -f $n)) }
    [void]$sb.AppendLine('')
}

if ($recentPs) {
    [void]$sb.AppendLine('Son PowerShell script loglari (4104):')
    foreach ($evt in $recentPs) {
        $msg = (($evt.Message -replace '\s+', ' ').Substring(0, [Math]::Min(240, (($evt.Message -replace '\s+', ' ').Length))))
        [void]$sb.AppendLine(('[{0}] {1}' -f $evt.TimeCreated, $msg))
    }
}

$report = $sb.ToString()
Set-Content -LiteralPath $OutputPath -Value $report -Encoding UTF8

Write-Host $report
Write-Host ''
Write-Host "Rapor kaydedildi: $OutputPath"
if ($hits.Count -gt 0) {
    Write-Host ''
    Write-Host 'Supheli=True olan kayitlara once bak. EncodedCommand, Hidden, DownloadString, Defender exclusion varsa silme + tarama yap.'
}
