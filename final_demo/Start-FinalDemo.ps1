# CS4390 final demo — project spec timeline:
# t=0:00  tracker + peer1 + peer2 (seeds)
# t=0:30  peer3..peer8 (6 leechers)
# t=1:30  peer9..peer13 (5 leechers); then terminate peer1 and peer2
#
# PEER_ID is set to Peer1..Peer13 so console logs match the required formats.
# Tracker IP/port/interval: repo clientThreadConfig.cfg (defaults 127.0.0.1, 5000, 20).
# Optional: -LargeFileMiB 32  |  -NoCleanTracker

param(
    [string]$RepoRoot = "",
    [int]$LargeFileMiB = 8,
    [switch]$NoCleanTracker
)

$ErrorActionPreference = "Stop"
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Read-RootClientConfig {
    param([string]$CfgPath)
    $ip = "127.0.0.1"
    $port = 5000
    $interval = 20
    if (-not (Test-Path $CfgPath)) { return $ip, $port, $interval }
    $lines = @(Get-Content -Path $CfgPath -ErrorAction SilentlyContinue)
    for ($idx = 0; $idx -lt [Math]::Min(3, $lines.Length); $idx++) {
        $line = ($lines[$idx] -split '#')[0].Trim()
        if (-not $line) { continue }
        $tok = ($line -split '\s+')[0]
        if ($idx -eq 0) { $ip = $tok }
        elseif ($idx -eq 1) { $port = [int]$tok }
        elseif ($idx -eq 2) { $interval = [int]$tok }
    }
    return $ip, $port, $interval
}

function Write-Utf8Lf {
    param([string]$Path, [string]$Text)
    $enc = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-PeerClientConfig {
    param([string]$Path, [string]$Ip, [int]$Port, [int]$Interval)
    $t = "$Ip # tracker IP`n$Port # tracker port`n$Interval # refresh interval (seconds)`n"
    Write-Utf8Lf -Path $Path -Text $t
}

function Write-PeerServerConfig {
    param([string]$Path, [int]$ListenPort)
    $t = "$ListenPort#port`n./sharedFolder#sharedFolderPath`n"
    Write-Utf8Lf -Path $Path -Text $t
}

function Ensure-DemoPeerLayout {
    param(
        [string]$Root,
        [string]$TrackerIp,
        [int]$TrackerPort,
        [int]$RefreshSec,
        [int]$LargeMiB
    )

    for ($n = 1; $n -le 13; $n++) {
        $pdir = Join-Path $Root "peer$n"
        $sf = Join-Path $pdir "sharedFolder"
        New-Item -ItemType Directory -Force -Path $sf | Out-Null
        Write-PeerClientConfig -Path (Join-Path $pdir "clientThreadConfig.cfg") -Ip $TrackerIp -Port $TrackerPort -Interval $RefreshSec
        $listenPort = 6000 + $n
        Write-PeerServerConfig -Path (Join-Path $pdir "serverThreadConfig.cfg") -ListenPort $listenPort
    }

    foreach ($n in @(1, 2)) {
        $sf = Join-Path $Root "peer$n\sharedFolder"
        Get-ChildItem -Path $sf -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Utf8Lf -Path (Join-Path $Root "peer1\sharedFolder\demo_small.txt") -Text "CS4390 demo small seed (peer1).`n"

    $largePath = Join-Path $Root "peer2\sharedFolder\demo_large.bin"
    $bytes = [int64]([Math]::Max(1, $LargeMiB)) * 1024 * 1024
    $rng = New-Object System.Random
    $chunkSize = [int]([Math]::Min($bytes, [int64]1048576))
    $chunk = New-Object byte[] $chunkSize
    $fs = [System.IO.File]::Create($largePath)
    try {
        $remain = $bytes
        while ($remain -gt 0) {
            $take = [int]([Math]::Min($remain, [int64]$chunk.Length))
            if ($take -lt $chunk.Length) {
                $slice = New-Object byte[] $take
                $rng.NextBytes($slice)
                $fs.Write($slice, 0, $take)
            } else {
                $rng.NextBytes($chunk)
                $fs.Write($chunk, 0, $take)
            }
            $remain -= $take
        }
    } finally { $fs.Close() }

    for ($n = 3; $n -le 13; $n++) {
        $sf = Join-Path $Root "peer$n\sharedFolder"
        Get-ChildItem -Path $sf -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$rootCfg = Join-Path $RepoRoot "clientThreadConfig.cfg"
$tIp, $tPort, $tInterval = Read-RootClientConfig -CfgPath $rootCfg
if (-not (Test-Path $rootCfg)) {
    $t = "$tIp # tracker IP`n$tPort # tracker port`n$tInterval # refresh interval (seconds)`n"
    Write-Utf8Lf -Path $rootCfg -Text $t
}

$TrackerExe = Join-Path $RepoRoot "tracker.exe"
$PeerExe = Join-Path $RepoRoot "peer1\peer.exe"
if (-not (Test-Path $PeerExe)) { $PeerExe = Join-Path $RepoRoot "peer.exe" }

if (-not (Test-Path $TrackerExe)) { throw "tracker.exe not found under $RepoRoot (run make)" }
if (-not (Test-Path $PeerExe)) { throw "peer.exe not found (run make; expect peer1\peer.exe or peer.exe)" }

Ensure-DemoPeerLayout -Root $RepoRoot -TrackerIp $tIp -TrackerPort $tPort -RefreshSec $tInterval -LargeMiB $LargeFileMiB

$ts = Join-Path $RepoRoot "tracker_shared"
if (-not $NoCleanTracker -and (Test-Path $ts)) {
    Remove-Item -Recurse -Force $ts
}

$SeedDirs = @(
    (Join-Path $RepoRoot "peer1"),
    (Join-Path $RepoRoot "peer2")
)
# Leech peers only: peer3 .. peer13 (indices 0..10)
$LeechDirs = for ($i = 3; $i -le 13; $i++) { Join-Path $RepoRoot "peer$i" }

function Start-PeerProcess {
    param([string]$WorkingDir, [string]$PeerId)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PeerExe
    $psi.WorkingDirectory = $WorkingDir
    $psi.UseShellExecute = $false
    $psi.EnvironmentVariables["PEER_ID"] = $PeerId
    [System.Diagnostics.Process]::Start($psi)
}

$psiTr = New-Object System.Diagnostics.ProcessStartInfo
$psiTr.FileName = $TrackerExe
$psiTr.WorkingDirectory = $RepoRoot
$psiTr.UseShellExecute = $false
[void][System.Diagnostics.Process]::Start($psiTr)

$seed1 = Start-PeerProcess -WorkingDir $SeedDirs[0] -PeerId "Peer1"
$seed2 = Start-PeerProcess -WorkingDir $SeedDirs[1] -PeerId "Peer2"

Start-Sleep -Seconds 30

# Peers 3..8 (six leechers)
for ($i = 0; $i -lt 6; $i++) {
    $peerNum = $i + 3
    [void](Start-PeerProcess -WorkingDir $LeechDirs[$i] -PeerId "Peer$peerNum")
}

Start-Sleep -Seconds 60

# Peers 9..13 (five leechers)
for ($i = 6; $i -lt 11; $i++) {
    $peerNum = $i + 3
    [void](Start-PeerProcess -WorkingDir $LeechDirs[$i] -PeerId "Peer$peerNum")
}

foreach ($s in @($seed1, $seed2)) {
    try {
        if (-not $s.HasExited) { $s.Kill() }
    } catch { }
}

Write-Host "Peer1 terminated"
Write-Host "Peer2 terminated"
