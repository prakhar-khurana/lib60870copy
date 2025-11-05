#!/usr/bin/env pwsh
# IEC 62351-5:2023 Build and Test Script

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$BuildDir = Join-Path $ProjectRoot "lib60870-C\build"

Write-Host "`n=== IEC 62351-5:2023 Build Script ===`n" -ForegroundColor Cyan

# Clean and create build directory
if (Test-Path $BuildDir) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# Configure
Write-Host "Configuring CMake..." -ForegroundColor Yellow
Push-Location $BuildDir
cmake -G "Visual Studio 17 2022" -A x64 .. 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake configuration failed" -ForegroundColor Red
    Pop-Location
    exit 1
}
Write-Host "✓ CMake configured" -ForegroundColor Green

# Build
Write-Host "Building (this takes 2-3 minutes)..." -ForegroundColor Yellow
cmake --build . --config Release 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed" -ForegroundColor Red
    Pop-Location
    exit 1
}
Write-Host "✓ Build completed" -ForegroundColor Green
Pop-Location

# Verify
Write-Host "`nVerifying build artifacts..." -ForegroundColor Yellow
$server = Join-Path $BuildDir "examples\Release\iec62351_5_demo_server.exe"
$client = Join-Path $BuildDir "examples\Release\iec62351_5_demo_client.exe"

if ((Test-Path $server) -and (Test-Path $client)) {
    Write-Host "✓ Demo applications built successfully" -ForegroundColor Green
    Write-Host "`nTo run the demo:" -ForegroundColor Cyan
    Write-Host "  1. Server: .\lib60870-C\build\examples\Release\iec62351_5_demo_server.exe"
    Write-Host "  2. Client: .\lib60870-C\build\examples\Release\iec62351_5_demo_client.exe"
    Write-Host "`nBuild complete!`n" -ForegroundColor Green
} else {
    Write-Host "ERROR: Demo applications not found" -ForegroundColor Red
    exit 1
}
