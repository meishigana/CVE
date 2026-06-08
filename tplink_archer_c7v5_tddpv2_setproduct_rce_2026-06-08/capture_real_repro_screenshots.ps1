$ErrorActionPreference = "Stop"

$Base = Join-Path (Get-Location) "cve_submission_materials\tplink_archer_c7v5_tddpv2_setproduct_rce_2026-06-08"
$ShotDir = Join-Path $Base "screenshots"
$LogPath = Join-Path $ShotDir "real_01_terminal_reproduction_output.txt"
$DonePath = Join-Path $ShotDir "real_01_terminal_reproduction.done"
$RunnerPath = Join-Path $ShotDir "run_real_repro_visible.ps1"
$ScreenshotPath = Join-Path $ShotDir "real_01_terminal_reproduction.png"

New-Item -ItemType Directory -Force -Path $ShotDir | Out-Null
Remove-Item -LiteralPath $LogPath, $DonePath, $ScreenshotPath -ErrorAction SilentlyContinue

$Runner = @'
$ErrorActionPreference = "Continue"
$Host.UI.RawUI.WindowTitle = "REAL PoC reproduction - TP-Link Archer C7 V5 TDDPv2 setProductName RCE"
Clear-Host
Write-Host "REAL PoC reproduction - TP-Link Archer C7 V5 TDDPv2 setProductName RCE"
Write-Host "This visible terminal is executing the verified local firmware-emulation PoC."
Write-Host ""
Write-Host "Command:"
Write-Host "docker exec firmrec-dev-run sh -lc 'chmod +x /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh; /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh'"
Write-Host ""
Write-Host "Running..."
Write-Host ""

$LogPath = "__LOG_PATH__"
$DonePath = "__DONE_PATH__"

& docker exec firmrec-dev-run sh -lc 'chmod +x /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh; /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh' 2>&1 |
    Tee-Object -FilePath $LogPath

Write-Host ""
Write-Host "Reproduction command finished."
Write-Host "Expected success markers: status=0x00, PWNED_CREATED, TDDP_RCE."
Write-Host "This window will stay open for screenshot capture."
Set-Content -Path $DonePath -Value "done" -Encoding ASCII
'@

$Runner = $Runner.Replace("__LOG_PATH__", $LogPath.Replace("\", "\\"))
$Runner = $Runner.Replace("__DONE_PATH__", $DonePath.Replace("\", "\\"))
Set-Content -Path $RunnerPath -Value $Runner -Encoding UTF8

$Proc = Start-Process -FilePath "powershell.exe" -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-File", $RunnerPath
) -PassThru

$Deadline = (Get-Date).AddSeconds(150)
while ((Get-Date) -lt $Deadline) {
    if (Test-Path -LiteralPath $DonePath) {
        break
    }
    Start-Sleep -Seconds 2
}

if (-not (Test-Path -LiteralPath $DonePath)) {
    throw "Timed out waiting for visible reproduction terminal to finish."
}

Start-Sleep -Seconds 3

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$Bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$Bitmap = New-Object System.Drawing.Bitmap($Bounds.Width, $Bounds.Height)
$Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
$Graphics.CopyFromScreen($Bounds.Location, [System.Drawing.Point]::Empty, $Bounds.Size)
$Bitmap.Save($ScreenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
$Graphics.Dispose()
$Bitmap.Dispose()

Write-Host "Saved real screen screenshot: $ScreenshotPath"
Write-Host "Saved visible terminal output log: $LogPath"
Write-Host "Visible terminal PID: $($Proc.Id)"
