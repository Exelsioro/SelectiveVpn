#Requires -RunAsAdministrator
$root = Split-Path -Parent $PSScriptRoot
& netsh.exe wfp show state file=(Join-Path $root 'artifacts\wfp-state.xml')
