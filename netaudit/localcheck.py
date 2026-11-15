"""Read-only check of the Windows workstation the audit runs from."""
from __future__ import annotations

from . import netinfo

_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
function Reg($path, $name) { (Get-ItemProperty -Path $path -Name $name).$name }
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
# The effective state: local settings overlaid with Group Policy. A first match under the policy
# keys wins, as Windows itself does.
function Effective($paths, $name) { foreach ($p in $paths) { $v = Reg $p $name; if ($null -ne $v) { return $v } }; return $null }
$fwp = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if (-not $fwp.Count) { $fwp = @(Get-NetFirewallProfile) }
$fw = @($fwp | ForEach-Object { [pscustomobject]@{ name=[string]$_.Name; enabled=([string]$_.Enabled -eq 'True') } })
$fwprod = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.displayName; active=((([int]$_.productState -shr 8) -band 0xFF) -in 0x10,0x11) } })
$tsPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$tsLocal = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$smb = Get-SmbServerConfiguration
$nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | ForEach-Object { [pscustomobject]@{ adapter=[string]$_.Description; option=[int]$_.TcpipNetbiosOptions } })
# Rules are matched by identifier, which is the same in every Windows language.
$fr = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow)
if (-not $fr.Count) { $fr = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow) }
$rules = @($fr | Where-Object { $_.Name -match 'RemoteDesktop-UserMode-In-TCP|FPS-SMB-In-TCP' } | ForEach-Object {
  [pscustomobject]@{ port = $(if ($_.Name -match 'RemoteDesktop') { '3389' } else { '445' }); profile=[string]$_.Profile; name=[string]$_.DisplayName } })
$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.displayName; active=((([int]$_.productState -shr 8) -band 0xFF) -in 0x10,0x11); updated=(([int]$_.productState -band 0xFF) -eq 0) } })
$listen = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } | Sort-Object LocalPort -Unique | ForEach-Object {
  [pscustomobject]@{ port=[int]$_.LocalPort; address=[string]$_.LocalAddress; process=[string](Get-Process -Id $_.OwningProcess).ProcessName } })
$shares = @(Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { [pscustomobject]@{ name=[string]$_.Name; path=[string]$_.Path } })
$hot = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$mp = Get-MpComputerStatus
$bl = $null
try { $bl = [int](New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
$guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
$llmnr = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
[pscustomobject]@{
  computer = [string]$env:COMPUTERNAME
  domain = [string]$cs.Domain
  domain_joined = [bool]$cs.PartOfDomain
  os = [string]$os.Caption
  build = [string]$os.BuildNumber
  laptop = [bool]((Get-CimInstance Win32_SystemEnclosure).ChassisTypes | Where-Object { $_ -in 8,9,10,11,12,14,18,21,30,31,32 })
  firewall = $fw
  firewall_products = $fwprod
  rdp_enabled = ((Effective @($tsPolicy, $tsLocal) 'fDenyTSConnections') -eq 0)
  rdp_nla = ((Effective @($tsPolicy, "$tsLocal\WinStations\RDP-Tcp") 'UserAuthentication') -eq 1)
  smb1 = if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null }
  smb_signing_required = if ($smb) { [bool]$smb.RequireSecuritySignature } else { $null }
  llmnr_disabled = ($llmnr -eq 0)
  netbios = $nb
  rules = $rules
  antivirus = $av
  listening = $listen
  shares = $shares
  last_update = if ($hot) { $hot.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
  defender_realtime = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
  defender_mode = if ($mp) { [string]$mp.AMRunningMode } else { '' }
  uac_enabled = ((Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -ne 0)
  wdigest_cleartext = ((Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1)
  lsa_protection = ((Effective @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa') 'RunAsPPL') -ge 1)
  guest_enabled = if ($guest) { [bool]$guest.Enabled } else { $null }
  bitlocker = $bl
} | ConvertTo-Json -Depth 5
"""

_LISTS = ("firewall", "firewall_products", "netbios", "rules", "listening", "shares", "antivirus")


def normalize(data) -> dict | None:
    """Make the shape predictable: PowerShell emits a bare object for one-element arrays."""
    if not isinstance(data, dict):
        return None
    for key in _LISTS:
        value = data.get(key)
        if value is None:
            data[key] = []
        elif isinstance(value, dict):
            data[key] = [value]
    return data


def collect() -> dict | None:
    """Configuration facts of the local workstation, or None when unavailable."""
    if not netinfo.IS_WINDOWS:
        return None
    return normalize(netinfo.run_powershell_json(_PS, timeout=120))
