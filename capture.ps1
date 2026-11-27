$ErrorActionPreference = 'Continue'
$script:pw = 'Itr!' + [guid]::NewGuid().ToString('N').Substring(0,12) + 'aA9'
$script:sec = ConvertTo-SecureString $script:pw -AsPlainText -Force
$out = Join-Path $env:GITHUB_WORKSPACE 'out'
New-Item -ItemType Directory -Force $out | Out-Null
function Section($name) { "`n===== $name =====" }

# ---------------------------------------------------------------- manifests
function Dump-Manifest($provider, $ids, $file) {
  $xmlPath = Join-Path $out "$file.xml"
  wevtutil gp "$provider" /ge /gm:true /f:xml > $xmlPath 2>&1
  $text = Get-Content $xmlPath -Raw
  try { [xml]$x = $text } catch { "could not parse manifest for $provider"; return }
  $ns = @{ e = $x.DocumentElement.NamespaceURI }
  $tmpl = @{}
  foreach ($t in $x.provider.templates.template) { $tmpl[$t.tid] = ($t.data | ForEach-Object { $_.name }) -join ',' }
  foreach ($ev in $x.provider.events.event) {
    $v = [int]$ev.value
    if ($ids.Count -eq 0 -or $ids -contains $v) {
      "{0} v{1} level={2} channel={3} template={4} fields=[{5}]" -f $v, $ev.version, $ev.level, $ev.channel, $ev.template, $tmpl[$ev.template]
      "    msg: " + (($ev.message -replace '\s+', ' ').Trim())
    }
  }
}

& {
Section 'User Profiles Service manifest'
Dump-Manifest 'Microsoft-Windows-User Profiles Service' @(1,2,1500,1502,1504,1508,1509,1511,1515,1521,1530,1533,1534,1542,1543,1552) 'ups'
Section 'User Profiles General manifest'
Dump-Manifest 'Microsoft-Windows-User Profiles General' @() 'upg'
Section 'WindowsUpdateClient manifest'
Dump-Manifest 'Microsoft-Windows-WindowsUpdateClient' @(19,20,21,22,25,31,43,44) 'wuc'
Section 'DeviceManagement-Enterprise-Diagnostics-Provider manifest (selected)'
Dump-Manifest 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider' @(72,75,76,201,208,209,404,454,813,814,1900,2545) 'dm'
Section 'DM channels'
wevtutil el | Select-String -Pattern 'DeviceManagement|FSLogix|User Profile'
Section 'DM manifest: every event mentioning session/sync'
$dm = Get-Content (Join-Path $out 'dm.xml') -Raw
[xml]$dx = $dm
foreach ($ev in $dx.provider.events.event) { $m = ($ev.message -replace '\s+',' ').Trim(); if ($m -match 'session|Session|sync|Sync|enroll') { "{0} level={1} channel={2}: {3}" -f $ev.value, $ev.level, $ev.channel, $m } }
} *> (Join-Path $out 'manifests.txt')

# ------------------------------------------------------------ update history
& {
Section 'WUA history'
$s = New-Object -ComObject Microsoft.Update.Session
$h = $s.CreateUpdateSearcher()
$n = $h.GetTotalHistoryCount()
"total history count: $n"
if ($n -gt 0) {
  $h.QueryHistory(0, [Math]::Min($n, 60)) | ForEach-Object {
    "{0:o} op={1} result={2} hr=0x{3:X8} unmapped=0x{4:X8} client={5} server={6} title={7} id={8}" -f $_.Date, $_.Operation, $_.ResultCode, $_.HResult, $_.UnmappedResultCode, $_.ClientApplicationID, $_.ServerSelection, $_.Title, $_.UpdateIdentity.UpdateID
  }
}
Section 'WindowsUpdateClient events 19/20/43 in System log (XML, newest 6)'
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Id=19,20,43} -MaxEvents 6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }
Section 'Setup log servicing failures (newest 5)'
Get-WinEvent -FilterHashtable @{LogName='Setup'; Level=2} -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }
} *> (Join-Path $out 'updates.txt')

# ------------------------------------------------------------------ profiles
& {
Section 'ProfileList before'
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s
Section 'policy: temp profiles'
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" 2>&1
$start = Get-Date
foreach ($u in 'itrtp1','itrtp2','itrtp3') {
  net user $u $script:pw /add /y | Out-Null
  net localgroup "Users" $u /add 2>$null | Out-Null
}
$cred1 = New-Object System.Management.Automation.PSCredential('itrtp1', $script:sec)
Section 'first profile load for itrtp1'
try { Start-Process cmd.exe -ArgumentList '/c','echo ok' -Credential $cred1 -LoadUserProfile -Wait -WorkingDirectory C:\ -WindowStyle Hidden; 'loaded' } catch { "load failed: $_" }
Start-Sleep 3
$sid = (New-Object System.Security.Principal.NTAccount('itrtp1')).Translate([System.Security.Principal.SecurityIdentifier]).Value
"sid: $sid"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
Section 'lock NTUSER.DAT and load again'
$dat = "C:\Users\itrtp1\NTUSER.DAT"
"exists: $(Test-Path $dat)"
$lock = $null
try { $lock = [System.IO.File]::Open($dat, 'Open', 'ReadWrite', 'None'); 'locked' } catch { "lock failed: $_" }
try { Start-Process cmd.exe -ArgumentList '/c','echo %USERPROFILE%' -Credential $cred1 -LoadUserProfile -Wait -WorkingDirectory C:\ -WindowStyle Hidden; 'second load returned' } catch { "second load failed: $_" }
Start-Sleep 3
if ($lock) { $lock.Close() }
Section 'ProfileList after'
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s
Section 'Users folder'
Get-ChildItem C:\Users -Force | Select-Object Name, Attributes | Format-Table -AutoSize | Out-String -Width 200
Section 'Application log: User Profiles Service events since start (XML)'
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-User Profiles Service'; StartTime=$start} -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml(); '   MESSAGE: ' + ($_.Message -replace '\s+',' ') }
Section 'Operational channel since start (id, message)'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-User Profile Service/Operational'; StartTime=$start} -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object { "{0:o} {1} L{2}: {3}" -f $_.TimeCreated, $_.Id, $_.Level, ($_.Message -replace '\s+',' ') }
Section 'Application log: any errors/warnings since start'
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2,3; StartTime=$start} -ErrorAction SilentlyContinue | ForEach-Object { "{0} {1} L{2}: {3}" -f $_.ProviderName, $_.Id, $_.Level, ($_.Message -replace '\s+',' ') }
} *> (Join-Path $out 'profiles.txt')

# ------------------------------------------------------------------- FSLogix
& {
Section 'download FSLogix'
$zip = Join-Path $env:RUNNER_TEMP 'fslogix.zip'
try { Invoke-WebRequest -Uri 'https://aka.ms/fslogix_download' -OutFile $zip -UseBasicParsing; "zip bytes: $((Get-Item $zip).Length)" } catch { "download failed: $_" }
$dir = Join-Path $env:RUNNER_TEMP 'fslogix'
Expand-Archive $zip -DestinationPath $dir -Force
Get-ChildItem $dir -Recurse | Select-Object FullName, Length | Format-Table -AutoSize | Out-String -Width 300
$setup = Get-ChildItem $dir -Recurse -Filter FSLogixAppsSetup.exe | Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
"setup: $($setup.FullName) version $($setup.VersionInfo.ProductVersion)"
$p = Start-Process $setup.FullName -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
"setup exit: $($p.ExitCode)"
Section 'services'
Get-Service frxsvc, frxccds -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize | Out-String
Section 'install dir'
Get-ChildItem 'C:\Program Files\FSLogix\Apps' | Select-Object Name, Length | Format-Table -AutoSize | Out-String -Width 200
Section 'registry HKLM\SOFTWARE\FSLogix'
reg query HKLM\SOFTWARE\FSLogix /s
Section 'groups'
Get-LocalGroup | Where-Object Name -like 'FSLogix*' | Format-Table Name, Description -AutoSize | Out-String -Width 300
Section 'event publishers and channels'
wevtutil ep | Select-String -Pattern 'FSLogix'
wevtutil el | Select-String -Pattern 'FSLogix'
foreach ($pub in (wevtutil ep | Select-String -Pattern 'FSLogix').Line) {
  Section "manifest $pub"
  Dump-Manifest $pub @() ("fsl-" + ($pub -replace '[^A-Za-z]',''))
}
Section 'frx help'
& 'C:\Program Files\FSLogix\Apps\frx.exe' help 2>&1 | Select-Object -First 80
Section 'configure profile container on a local folder, then load a profile'
New-Item -ItemType Directory -Force C:\fslprofiles | Out-Null
icacls C:\fslprofiles /grant "Users:(OI)(CI)M" | Out-Null
reg add HKLM\SOFTWARE\FSLogix\Profiles /v Enabled /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\FSLogix\Profiles /v VHDLocations /t REG_MULTI_SZ /d C:\fslprofiles /f
reg add HKLM\SOFTWARE\FSLogix\Profiles /v SizeInMBs /t REG_DWORD /d 2000 /f
reg add HKLM\SOFTWARE\FSLogix\Profiles /v VolumeType /t REG_SZ /d VHDX /f
net localgroup "FSLogix Profile Include List" itrtp2 /add
net localgroup "FSLogix Profile Include List" itrtp3 /add
$fstart = Get-Date
$cred2 = New-Object System.Management.Automation.PSCredential('itrtp2', $script:sec)
try { Start-Process cmd.exe -ArgumentList '/c','echo %USERPROFILE%' -Credential $cred2 -LoadUserProfile -Wait -WorkingDirectory C:\ -WindowStyle Hidden; 'itrtp2 load returned' } catch { "itrtp2 load failed: $_" }
Start-Sleep 5
Section 'after itrtp2'
reg query HKLM\SOFTWARE\FSLogix\Profiles /s
Get-ChildItem C:\fslprofiles -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize | Out-String -Width 300
Section 'unreachable location for itrtp3'
reg add HKLM\SOFTWARE\FSLogix\Profiles /v VHDLocations /t REG_MULTI_SZ /d Z:\nope\profiles /f
$cred3 = New-Object System.Management.Automation.PSCredential('itrtp3', $script:sec)
try { Start-Process cmd.exe -ArgumentList '/c','echo %USERPROFILE%' -Credential $cred3 -LoadUserProfile -Wait -WorkingDirectory C:\ -WindowStyle Hidden; 'itrtp3 load returned' } catch { "itrtp3 load failed: $_" }
Start-Sleep 5
Section 'after itrtp3'
reg query HKLM\SOFTWARE\FSLogix\Profiles /s
Section 'FSLogix events since configure'
foreach ($ch in (wevtutil el | Select-String -Pattern 'FSLogix').Line) {
  "--- $ch"
  Get-WinEvent -FilterHashtable @{LogName=$ch; StartTime=$fstart} -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object { "{0:o} {1} L{2}: {3}" -f $_.TimeCreated, $_.Id, $_.Level, ($_.Message -replace '\s+',' ') ; $_.ToXml() }
}
Section 'FSLogix log files'
Get-ChildItem C:\ProgramData\FSLogix\Logs -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize | Out-String -Width 300
Get-ChildItem C:\ProgramData\FSLogix\Logs\Profile -Filter *.log -ErrorAction SilentlyContinue | ForEach-Object { "--- $($_.FullName)"; Get-Content $_.FullName -Tail 120 }
Section 'User Profiles Service events since configure'
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-User Profiles Service'; StartTime=$fstart} -ErrorAction SilentlyContinue | ForEach-Object { "{0} L{1}: {2}" -f $_.Id, $_.Level, ($_.Message -replace '\s+',' ') }
} *> (Join-Path $out 'fslogix.txt')

# -------------------------------------------------------------------- Intune
& {
Section 'Enrollments'
reg query HKLM\SOFTWARE\Microsoft\Enrollments /s 2>&1 | Select-Object -First 120
Section 'OMADM accounts'
reg query HKLM\SOFTWARE\Microsoft\Provisioning\OMADM /s 2>&1 | Select-Object -First 60
Section 'EnterpriseMgmt tasks'
schtasks /query /fo LIST /tn \Microsoft\Windows\EnterpriseMgmt\ 2>&1 | Select-Object -First 40
Section 'IME service'
Get-Service IntuneManagementExtension -ErrorAction SilentlyContinue | Format-List * | Out-String
Section 'dmwappushservice'
Get-Service dmwappushservice -ErrorAction SilentlyContinue | Format-List Name, Status, StartType | Out-String
Section 'deviceenroller'
Get-Item C:\Windows\System32\deviceenroller.exe | Select-Object FullName, @{n='v';e={$_.VersionInfo.FileVersion}} | Format-List | Out-String
Section 'DM admin channel recent'
Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 15 -ErrorAction SilentlyContinue | ForEach-Object { "{0:o} {1} L{2}: {3}" -f $_.TimeCreated, $_.Id, $_.Level, ($_.Message -replace '\s+',' ') }
Section 'OS'
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List | Out-String
} *> (Join-Path $out 'intune.txt')
