# enc installer for Windows (PowerShell)
#
#   irm https://raw.githubusercontent.com/Xeze-org/enc/main/install.ps1 | iex
#
# Downloads the latest enc.exe and adds it to your PATH so `enc` works everywhere.

$ErrorActionPreference = 'Stop'

$repo = 'Xeze-org/enc'
$dir  = Join-Path $env:LOCALAPPDATA 'Programs\enc'
$exe  = Join-Path $dir 'enc.exe'
$url  = "https://github.com/$repo/releases/latest/download/enc.exe"

Write-Host "Installing enc to $dir ..."
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Invoke-WebRequest -Uri $url -OutFile $exe

# Add the install dir to the USER PATH permanently (so `enc` works in every shell)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your PATH."
}
# ...and make it usable in the current session immediately
if (($env:Path -split ';') -notcontains $dir) { $env:Path += ";$dir" }

Write-Host ""
Write-Host "Done. Open a new terminal (or use this one) and run:  enc help"
