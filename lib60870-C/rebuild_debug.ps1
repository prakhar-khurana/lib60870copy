# Force complete rebuild script
Write-Host "=== IEC 62351-5 Complete Rebuild Script ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Clean build directory
Write-Host "[1/5] Cleaning build directory..." -ForegroundColor Yellow
if (Test-Path "build") {
    Remove-Item -Path "build" -Recurse -Force
    Write-Host "  ✓ Removed old build directory" -ForegroundColor Green
}

# Step 2: Create fresh build directory
Write-Host "[2/5] Creating fresh build directory..." -ForegroundColor Yellow
New-Item -Path "build" -ItemType Directory | Out-Null
Set-Location "build"
Write-Host "  ✓ Created new build directory" -ForegroundColor Green

# Step 3: Run CMake configuration
Write-Host "[3/5] Running CMake configuration..." -ForegroundColor Yellow
cmake .. 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ CMake configuration successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ CMake configuration failed" -ForegroundColor Red
    exit 1
}

# Step 4: Build Debug configuration
Write-Host "[4/5] Building Debug configuration..." -ForegroundColor Yellow
cmake --build . --config Debug 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Build successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ Build failed" -ForegroundColor Red
    exit 1
}

# Step 5: Verify executables
Write-Host "[5/5] Verifying executables..." -ForegroundColor Yellow
$clientExe = "examples\iec62351_5_demo\Debug\iec62351_5_demo_client.exe"
$serverExe = "examples\iec62351_5_demo\Debug\iec62351_5_demo_server.exe"

if (Test-Path $clientExe) {
    $clientTime = (Get-Item $clientExe).LastWriteTime
    Write-Host "  ✓ Client executable: $clientTime" -ForegroundColor Green
} else {
    Write-Host "  ✗ Client executable not found" -ForegroundColor Red
}

if (Test-Path $serverExe) {
    $serverTime = (Get-Item $serverExe).LastWriteTime
    Write-Host "  ✓ Server executable: $serverTime" -ForegroundColor Green
} else {
    Write-Host "  ✗ Server executable not found" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Rebuild Complete ===" -ForegroundColor Cyan
Write-Host "You can now run:" -ForegroundColor White
Write-Host "  .\$serverExe" -ForegroundColor Gray
Write-Host "  .\$clientExe" -ForegroundColor Gray
