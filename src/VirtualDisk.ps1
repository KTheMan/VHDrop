param(
    [Parameter(Mandatory=$true)][ValidateSet('Mount','Dismount')][string]$Action,
    [Parameter(Mandatory=$true)][string]$ImagePath
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Elevated processes may not see the user's mapped drives. Pass a UNC path instead.
        if ($ImagePath -match '^([A-Za-z]):\\') {
            $drive = Get-PSDrive -Name $Matches[1] -ErrorAction SilentlyContinue
            if ($drive -and $drive.DisplayRoot -and $drive.DisplayRoot.StartsWith('\\')) {
                $ImagePath = $drive.DisplayRoot.TrimEnd('\') + $ImagePath.Substring(2)
            }
        }
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Action {1} -ImagePath "{2}"' -f $PSCommandPath, $Action, $ImagePath
        Start-Process -FilePath $ps -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden | Out-Null
        exit
    }
    if (-not (Test-Path -LiteralPath $ImagePath -PathType Leaf)) { throw "The disk image was not found: $ImagePath" }
    if ([IO.Path]::GetExtension($ImagePath) -notin '.vhd', '.vhdx') { throw 'Select a VHD or VHDX file.' }
    if ($Action -eq 'Mount') {
        $checker = Join-Path $PSScriptRoot 'VHDrop.exe'
        if (-not (Test-Path -LiteralPath $checker -PathType Leaf)) { throw 'Cannot verify host-side VHDX recovery state because the app is missing.' }
        $process = Start-Process -FilePath $checker -ArgumentList @('--check-before-mount', ('"{0}"' -f $ImagePath)) -WindowStyle Hidden -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw 'Host-side image safety could not be verified. Use VHDrop to inspect the image; do not mount it until cleanup is confirmed.' }
    }
    # Hyper-V's direct VHD command can open images that Mount-DiskImage cannot.
    $directMount = Get-Command Mount-VHD -ErrorAction SilentlyContinue
    $directDismount = Get-Command Dismount-VHD -ErrorAction SilentlyContinue
    if ($directMount -and $directDismount) {
        if ($Action -eq 'Mount') { Mount-VHD -Path $ImagePath -ErrorAction Stop | Out-Null }
        else { Dismount-VHD -Path $ImagePath -ErrorAction Stop | Out-Null }
    } else {
        if ($Action -eq 'Mount') { Mount-DiskImage -ImagePath $ImagePath -ErrorAction Stop | Out-Null }
        else { Dismount-DiskImage -ImagePath $ImagePath -ErrorAction Stop | Out-Null }
    }
} catch {
    if ($_.Exception.NativeErrorCode -eq 1223) { exit }
    [System.Windows.Forms.MessageBox]::Show("Could not $($Action.ToLower()) the virtual disk:`n$ImagePath`n`n$($_.Exception.Message)", 'VHDrop', 'OK', 'Error') | Out-Null
    exit 1
}



