param([Parameter(Mandatory=$true)][string]$InstallDir,
      [string]$ClassesRoot = 'HKCU:\Software\Classes',
      [string]$SoftwareRoot = '')
$ErrorActionPreference = 'Stop'
$helper = Join-Path $InstallDir 'VirtualDisk.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'The virtual disk helper is missing.' }
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$progId = 'VHDXHandoff.VirtualDisk'
$prog = Join-Path $ClassesRoot $progId
New-Item -Path "$prog\shell\open\command" -Force | Out-Null
Set-Item -Path $prog -Value 'Virtual hard disk image'
Set-Item -Path "$prog\shell" -Value 'open'
Set-Item -Path "$prog\shell\open" -Value 'Mount virtual disk'
New-ItemProperty -Path "$prog\shell\open" -Name 'HasLUAShield' -Value '' -PropertyType String -Force | Out-Null
$mount = '"{0}" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{1}" -Action Mount -ImagePath "%1"' -f $ps,$helper
$dismount = '"{0}" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{1}" -Action Dismount -ImagePath "%1"' -f $ps,$helper
Set-Item -Path "$prog\shell\open\command" -Value $mount
foreach ($ext in '.vhd','.vhdx') {
    $extension = Join-Path $ClassesRoot $ext
    if (-not (Test-Path -LiteralPath $extension)) { New-Item -Path $extension -Force | Out-Null }
    if (-not (Test-Path -LiteralPath "$extension\OpenWithProgids")) { New-Item -Path "$extension\OpenWithProgids" -Force | Out-Null }
    New-ItemProperty -Path "$extension\OpenWithProgids" -Name $progId -PropertyType None -Value ([byte[]]@()) -Force | Out-Null
    foreach ($action in 'Mount','Dismount') {
        # Use app-specific keys; do not overwrite another application's verbs.
        $key = Join-Path $ClassesRoot "SystemFileAssociations\$ext\shell\VHDXHandoff.$action"
        New-Item -Path "$key\command" -Force | Out-Null
        Remove-ItemProperty -Path $key -Name LegacyDisable -ErrorAction SilentlyContinue
        Set-Item -Path $key -Value "$action virtual disk with VHDrop"
        New-ItemProperty -Path $key -Name 'HasLUAShield' -Value '' -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'MultiSelectModel' -Value 'Single' -PropertyType String -Force | Out-Null
        if ($action -eq 'Mount') { Set-Item -Path "$key\command" -Value $mount }
        else { Set-Item -Path "$key\command" -Value $dismount }
    }
}
if (-not $SoftwareRoot -and $ClassesRoot -eq 'HKCU:\Software\Classes') { $SoftwareRoot = 'HKCU:\Software' }
if ($SoftwareRoot) {
    $capabilities = Join-Path $SoftwareRoot 'VHDX Handoff\Capabilities'
    New-Item -Path "$capabilities\FileAssociations" -Force | Out-Null
    New-ItemProperty -Path $capabilities -Name ApplicationName -Value 'VHDrop' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $capabilities -Name ApplicationDescription -Value 'Mount virtual hard disk images' -PropertyType String -Force | Out-Null
    foreach ($ext in '.vhd','.vhdx') { New-ItemProperty -Path "$capabilities\FileAssociations" -Name $ext -Value $progId -PropertyType String -Force | Out-Null }
    # RegisteredApplications is shared with other programs: never recreate an existing key.
    $registered = Join-Path $SoftwareRoot 'RegisteredApplications'
    if (-not (Test-Path -LiteralPath $registered)) { New-Item -Path $registered | Out-Null }
    $capabilitiesValue = if ($SoftwareRoot -eq 'HKCU:\Software') { 'Software\VHDX Handoff\Capabilities' } else { $capabilities }
    New-ItemProperty -Path $registered -Name 'VHDX Handoff' -Value $capabilitiesValue -PropertyType String -Force | Out-Null
}
if ($ClassesRoot -eq 'HKCU:\Software\Classes' -and $SoftwareRoot -eq 'HKCU:\Software') {
    Add-Type -MemberDefinition '[System.Runtime.InteropServices.DllImport("shell32.dll")] public static extern void SHChangeNotify(int eventId, uint flags, System.IntPtr item1, System.IntPtr item2);' -Name ShellNotify -Namespace VhdxHandoff
    [VhdxHandoff.ShellNotify]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    foreach ($ext in '.vhd','.vhdx') {
        $choice = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
        if (Test-Path -LiteralPath $choice) { Write-Output "Windows has a protected $ext default app choice. You may need to change it in Settings > Apps > Default apps." }
    }
}
