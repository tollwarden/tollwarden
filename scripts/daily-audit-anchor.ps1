# TollWarden daily audit anchor + health check.
#
# Runs once a day from Windows Task Scheduler. It:
#   1. checks GET /health (service up, mode = live)
#   2. reads GET /v1/audit/head (free, no token) and appends
#      "<utc timestamp>,<seq>,<head hash>" to audit-anchors.log in the repo root —
#      the local, append-only record of the chain head that a rewritten server log
#      cannot retroactively change
#   3. refuses (exit 2) if the head ever moves backwards or the hash at the same
#      seq changes — either is tampering or a data loss on the server
#   4. if TOLLWARDEN_ADMIN_TOKEN is set, also runs backup-audit-log.ps1 for the
#      full offsite copy (optional; the anchor alone needs no credentials)
#
# Every outcome is appended to audit-anchor-runs.log next to the anchor file, so a
# silent failure is visible the next time anyone looks.
#
# Register (once, from the repo root):
#   $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
#              -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\scripts\daily-audit-anchor.ps1`""
#   $trigger = New-ScheduledTaskTrigger -Daily -At 9:15am
#   Register-ScheduledTask -TaskName 'TollWarden daily audit anchor' -Action $action -Trigger $trigger
#
# To also take the offsite backup, store the token machine-side once:
#   [Environment]::SetEnvironmentVariable("TOLLWARDEN_ADMIN_TOKEN", "<token>", "User")

param(
  [string]$ServiceUrl = "https://tollwarden.com",
  [string]$AnchorFile = (Join-Path (Split-Path $PSScriptRoot -Parent) "audit-anchors.log"),
  [string]$RunLog = (Join-Path (Split-Path $PSScriptRoot -Parent) "audit-anchor-runs.log"),
  [string]$BackupDir = ""
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-RunLog([string]$status, [string]$detail) {
  $line = "{0} {1} {2}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $status, $detail
  Add-Content -Path $RunLog -Value $line -Encoding ASCII
  Write-Output $line
}

try {
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $bust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()   # this host caches aggressively

  # 1. Health
  $health = Invoke-RestMethod -Uri "$ServiceUrl/health?t=$bust" -TimeoutSec 30
  if (-not $health.ok) { throw "health check returned ok=false: $($health | ConvertTo-Json -Compress)" }
  if ($health.mode -ne "live") { Write-RunLog "WARN" "service mode is '$($health.mode)', expected 'live'" }

  # 2. Audit head
  $head = Invoke-RestMethod -Uri "$ServiceUrl/v1/audit/head?t=$bust" -TimeoutSec 30
  $seq = [int64]$head.seq
  $hash = [string]$head.hash
  if ($seq -lt 0 -or $hash -notmatch '^[0-9a-f]{64}$') { throw "malformed audit head: $($head | ConvertTo-Json -Compress)" }

  # 3. Compare with the last anchor: the chain may only grow.
  if (Test-Path $AnchorFile) {
    $last = Get-Content $AnchorFile | Where-Object { $_ -match '^\S+,\d+,[0-9a-f]{64}$' } | Select-Object -Last 1
    if ($last) {
      $parts = $last.Split(",")
      $lastSeq = [int64]$parts[1]
      $lastHash = $parts[2]
      if ($seq -lt $lastSeq) {
        Write-RunLog "ALERT" "audit chain SHRANK: last anchored seq $lastSeq ($lastHash), server now reports seq $seq ($hash). Compare backups immediately."
        exit 2
      }
      if ($seq -eq $lastSeq -and $hash -ne $lastHash) {
        Write-RunLog "ALERT" "audit head REWRITTEN at seq ${seq}: anchored $lastHash, server now reports $hash. Compare backups immediately."
        exit 2
      }
    }
  }

  # 4. Anchor
  Add-Content -Path $AnchorFile -Value "$stamp,$seq,$hash" -Encoding ASCII
  Write-RunLog "OK" "anchored seq $seq $hash"

  # 5. Optional offsite backup of the full log
  if ($env:TOLLWARDEN_ADMIN_TOKEN) {
    $backupArgs = @{ ServiceUrl = $ServiceUrl }
    if ($BackupDir) { $backupArgs.BackupDir = $BackupDir }
    & (Join-Path $PSScriptRoot "backup-audit-log.ps1") @backupArgs
    if ($LASTEXITCODE -eq 2) { Write-RunLog "ALERT" "backup-audit-log.ps1 reported a shrinking log"; exit 2 }
    if ($LASTEXITCODE) { Write-RunLog "WARN" "backup-audit-log.ps1 exited $LASTEXITCODE" }
    else { Write-RunLog "OK" "offsite backup written" }
  } else {
    Write-RunLog "SKIP" "offsite backup skipped: TOLLWARDEN_ADMIN_TOKEN not set"
  }
  exit 0
} catch {
  Write-RunLog "ERROR" $_.Exception.Message
  exit 1
}
