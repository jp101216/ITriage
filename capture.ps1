$ErrorActionPreference = 'Continue'
$out = Join-Path $env:GITHUB_WORKSPACE 'out'
New-Item -ItemType Directory -Force $out | Out-Null
function Section($name) { "`n===== $name =====" }
function Dump($provider, [int[]]$ids) {
  $xmlPath = Join-Path $out ("m-" + ($provider -replace '[^A-Za-z]','') + ".xml")
  wevtutil gp "$provider" /ge /gm:true /f:xml > $xmlPath 2>&1
  [xml]$x = Get-Content $xmlPath -Raw
  "channels:"
  foreach ($c in $x.provider.channels.channel) { "  chid={0} value={1} name={2}" -f $c.id, $c.value, $c.name }
  $tmpl = @{}
  foreach ($t in $x.provider.templates.template) { if ($t.tid) { $tmpl[[string]$t.tid] = (@($t.data) | ForEach-Object { $_.name }) -join ',' } }
  foreach ($ev in $x.provider.events.event) {
    $v = [int]$ev.value
    if ($ids.Count -eq 0 -or $ids -contains $v) {
      $f = ''; if ($ev.template) { $f = $tmpl[[string]$ev.template] }
      "{0} v{1} level={2} channel={3} fields=[{4}] msg: {5}" -f $v, $ev.version, $ev.level, $ev.channel, $f, (($ev.message -replace '\s+', ' ').Trim())
    }
  }
}
& {
Section 'User Profiles Service'
Dump 'Microsoft-Windows-User Profiles Service' @(1500,1502,1504,1508,1509,1511,1515,1521,1530,1533,1534,1542,1543,1545,1552)
Section 'DeviceManagement'
Dump 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider' @(208,209,211,404,454,1900)
Section 'WindowsUpdateClient'
Dump 'Microsoft-Windows-WindowsUpdateClient' @(19,20,43)
} *> (Join-Path $out 'a.txt')
& {
Section 'FSLogix install'
$zip = Join-Path $env:RUNNER_TEMP 'fslogix.zip'
Invoke-WebRequest -Uri 'https://aka.ms/fslogix_download' -OutFile $zip -UseBasicParsing
$dir = Join-Path $env:RUNNER_TEMP 'fslogix'
Expand-Archive $zip -DestinationPath $dir -Force
$setup = Get-ChildItem $dir -Recurse -Filter FSLogixAppsSetup.exe | Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
$p = Start-Process $setup.FullName -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
"setup exit: $($p.ExitCode)"
Section 'FSLogix Apps manifest'
Dump 'Microsoft-FSLogix-Apps' @()
Section 'diskpart VHD free space via volume GUID path'
$v = Join-Path $env:RUNNER_TEMP 't.vhdx'
@"
create vdisk file="$v" maximum=200 type=expandable
select vdisk file="$v"
attach vdisk
create partition primary
format fs=ntfs quick label=ITRTEST
"@ | Set-Content (Join-Path $env:RUNNER_TEMP 'dp.txt') -Encoding ascii
diskpart /s (Join-Path $env:RUNNER_TEMP 'dp.txt') | Select-Object -Last 5
Start-Sleep 3
$vol = Get-CimInstance Win32_Volume | Where-Object Label -eq 'ITRTEST'
"DeviceID (volume GUID path): $($vol.DeviceID)  Capacity: $($vol.Capacity)  Free: $($vol.FreeSpace)"
Add-Type -Namespace W -Name K -MemberDefinition '[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool GetDiskFreeSpaceExW(string d, out ulong a, out ulong t, out ulong f);'
$a=0;$t=0;$f=0
$ok = [W.K]::GetDiskFreeSpaceExW($vol.DeviceID, [ref]$a, [ref]$t, [ref]$f)
"GetDiskFreeSpaceExW('$($vol.DeviceID)') ok=$ok total=$t free=$f lastError=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
$noSlash = $vol.DeviceID.TrimEnd('\')
$ok2 = [W.K]::GetDiskFreeSpaceExW($noSlash, [ref]$a, [ref]$t, [ref]$f)
"without trailing slash ok=$ok2 lastError=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
} *> (Join-Path $out 'b.txt')
