#!/usr/bin/env pwsh
#
# Complete IEC 62351-5:2023 Session Verification Script
#
# This script starts the demo server and client as background jobs,
# then monitors their log output in real-time to verify:
# 1. Successful session establishment (full handshake).
# 2. Successful secure data (ASDU) exchange.
#
# It includes timeout and failure detection for robust testing.
#

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# --- Configuration ---

# Paths to the executables
$ServerPath = "$ProjectRoot\lib60870-C\build\examples\Release\iec62351_5_demo_server.exe"
$ClientPath = "$ProjectRoot\lib60870-C\build\examples\Release\iec62351_5_demo_client.exe"

# Log file paths
$LogDirectory = "$ProjectRoot\session_logs"
$ServerLog = "$LogDirectory\server.log"
$ClientLog = "$LogDirectory\client.log"

# Test parameters
$TimeoutSeconds = 30 # Max time to wait for success
$FailurePatterns = @(
    "Error",
    "Failed",
    "Connection refused",
    "Handshake failed",
    "MAC verification error",
    "Invalid certificate",
    "Timeout"
)
$SessionSuccessPattern = "Session established"
$DataSuccessPattern = "ASDU received"

# --- Setup ---

# Clear previous logs
if (Test-Path $LogDirectory) {
    Remove-Item "$LogDirectory\*" -ErrorAction SilentlyContinue
} else {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# --- Main Execution ---

$ServerJob = $null
$ClientJob = $null

try {
    # Start server and client as background jobs, redirecting all output
    Write-Host "Starting server job..."
    $ServerJob = Start-Job -ScriptBlock { & $using:ServerPath *>&1 } | Out-Null
    Receive-Job $ServerJob # Clear any initial output
    
    # Wait for server to initialize
    Start-Sleep -Seconds 2
    
    Write-Host "Starting client job..."
    $ClientJob = Start-Job -ScriptBlock { & $using:ClientPath *>&1 } | Out-Null
    Receive-Job $ClientJob # Clear any initial output

    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   LIVE SESSION VERIFICATION                                ║" -ForegroundColor Cyan
    Write-Host "║   Monitoring logs in real-time... (Timeout: $($TimeoutSeconds)s)               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Start monitoring
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $ServerPos = 0
    $ClientPos = 0
    
    $SessionEstablished = $false
    $DataExchanged = $false

    while ($Stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        
        # --- Check Server Log ---
        if ($ServerJob.HasMoreData) {
            $newContent = Receive-Job $ServerJob
            $newContent | Add-Content -Path $ServerLog
            $newContent | ForEach-Object { Write-Host "[SERVER] $_" -ForegroundColor Yellow }
            
            # Check for failure
            $failure = $newContent | Select-String -Pattern $FailurePatterns -Quiet
            if ($failure) {
                Write-Host ""
                Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                Write-Host "║   VERIFICATION FAILED (SERVER)                             ║" -ForegroundColor Red
                Write-Host "║   Failure pattern detected in server log.                  ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                break
            }
        }

        # --- Check Client Log ---
        if ($ClientJob.HasMoreData) {
            $newContent = Receive-Job $ClientJob
            $newContent | Add-Content -Path $ClientLog
            $newContent | ForEach-Object { Write-Host "[CLIENT] $_" -ForegroundColor Cyan }
            
            # Check for failure
            $failure = $newContent | Select-String -Pattern $FailurePatterns -Quiet
            if ($failure) {
                Write-Host ""
                Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                Write-Host "║   VERIFICATION FAILED (CLIENT)                             ║" -ForegroundColor Red
                Write-Host "║   Failure pattern detected in client log.                  ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                break
            }
        }
        
        # --- Check for Success Conditions ---
        
        # 1. Check for Session Establishment
        if (-not $SessionEstablished) {
            if ((Select-String -Path $ServerLog -Pattern $SessionSuccessPattern -Quiet) -and
                (Select-String -Path $ClientLog -Pattern $SessionSuccessPattern -Quiet)) {
                
                $SessionEstablished = $true
                Write-Host ""
                Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                Write-Host "║   VERIFICATION SUCCESSFUL (SESSION)                        ║" -ForegroundColor Green
                Write-Host "║   Full handshake complete. Testing data exchange...        ║" -ForegroundColor Green
                Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                Write-Host ""
            }
        }
        
        # 2. Check for Data Exchange (only after session is established)
        if ($SessionEstablished) {
            if ((Select-String -Path $ServerLog -Pattern $DataSuccessPattern -Quiet) -and
                (Select-String -Path $ClientLog -Pattern $DataSuccessPattern -Quiet)) {
                
                $DataExchanged = $true
                Write-Host ""
                Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                Write-Host "║   VERIFICATION SUCCESSFUL (DATA)                           ║" -ForegroundColor Green
                Write-Host "║   Secure ASDU/APDU exchange confirmed.                     ║" -ForegroundColor Green
                Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                Write-Host ""
                break # All tests passed
            }
        }
        
        Start-Sleep -Milliseconds 500
    }

    # --- Final Result ---
    if (-not $SessionEstablished) {
        Write-Host ""
        Write-Host "TEST FAILED: Session was NOT established." -ForegroundColor Red
        if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            Write-Host "REASON: Test timed out after $TimeoutSeconds seconds." -ForegroundColor Red
        }
    } elseif (-not $DataExchanged) {
        Write-Host ""
        Write-Host "TEST FAILED: Secure data was NOT exchanged." -ForegroundColor Red
        if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            Write-Host "REASON: Test timed out after $TimeoutSeconds seconds." -ForegroundColor Red
        }
    } else {
        Write-Host "Session verification complete!" -ForegroundColor Green
    }

}
catch {
    Write-Host "An unexpected error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {
    # --- Cleanup ---
    Write-Host ""
    Write-Host "Cleaning up background jobs..."
    if ($ServerJob) { Stop-Job $ServerJob; Remove-Job $ServerJob }
    if ($ClientJob) { Stop-Job $ClientJob; Remove-Job $ClientJob }
    
    $Stopwatch.Stop()
    Write-Host "Test complete. Total time: $($Stopwatch.Elapsed.TotalSeconds)s"
    Write-Host "Full logs available in: $LogDirectory"
    Write-Host ""
}