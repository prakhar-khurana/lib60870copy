# IEC 62351-5 Demo - Rebuild and Run Script
# This script rebuilds the project and runs server + client

Write-Host "=== IEC 62351-5:2023 Demo - Rebuild and Run ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Kill any existing server/client processes
Write-Host "[1/5] Stopping any running server/client processes..." -ForegroundColor Yellow
Get-Process -Name "iec62351_5_demo_server" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "iec62351_5_demo_client" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# Step 2: Clean and rebuild
Write-Host "[2/5] Cleaning build directory..." -ForegroundColor Yellow
if (Test-Path "final-build") {
    Remove-Item -Path "final-build\*" -Recurse -Force -ErrorAction SilentlyContinue
} else {
    New-Item -Path "final-build" -ItemType Directory | Out-Null
}

Write-Host "[3/5] Running CMake configuration..." -ForegroundColor Yellow
Set-Location final-build
cmake .. -G "Visual Studio 17 2022" -A x64 `
    -DBUILD_TESTS=ON `
    -DBUILD_EXAMPLES=ON `
    -DCONFIG_CS104_APROFILE=ON `
    -DCONFIG_CS104_SUPPORT_TLS=ON

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake configuration failed!" -ForegroundColor Red
    Set-Location ..
    exit 1
}

Write-Host "[4/5] Building project (Debug configuration)..." -ForegroundColor Yellow
cmake --build . --config Debug --target iec62351_5_demo_server iec62351_5_demo_client

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed!" -ForegroundColor Red
    Set-Location ..
    exit 1
}

Set-Location ..

Write-Host "[5/5] Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Ready to Run ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run the demo:" -ForegroundColor White
Write-Host "  1. Open TWO PowerShell windows" -ForegroundColor White
Write-Host "  2. In window 1 (Server):" -ForegroundColor White
Write-Host "     cd final-build" -ForegroundColor Gray
Write-Host "     .\examples\iec62351_5_demo\Debug\iec62351_5_demo_server.exe" -ForegroundColor Gray
Write-Host "  3. In window 2 (Client):" -ForegroundColor White
Write-Host "     cd final-build" -ForegroundColor Gray
Write-Host "     .\examples\iec62351_5_demo\Debug\iec62351_5_demo_client.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
