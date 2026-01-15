[CmdletBinding()]
param(
    [ValidateSet("Panic","Restore")]
    [string]$Mode = "Panic",

    [switch]$DryRun,

    # Restore: specify a particular RunId folder under .\runs\<RunId>
    [string]$RunId,

    # How aggressive to freeze processes:
    # UserSafe = only non-critical processes owned by you in your session
    [ValidateSet("UserSafe","Off")]
    [string]$FreezeMode = "UserSafe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# Config (PS 5.1 compatible)
# -------------------------
$Cfg = @{
    Version = "CurtainDrop v1.2 (PS5.1-safe)"

    # Never suspend these (hard safety net)
    ProcessNameAllowList = @(
        # Our lifeline / terminals
        "powershell","pwsh","conhost","cmd","windowsterminal","wt","openconsole","pssuspend",

        # Critical Windows session + UX
        "system","registry","secure system","smss","csrss","wininit","services","svchost","lsass",
        "winlogon","fontdrvhost","dwm","sihost","explorer","ctfmon","taskhostw","runtimebroker",
        "startmenuexperiencehost","shellexperiencehost","searchhost","searchindexer",

        # Audio service host (avoid weird hangs)
        "audiodg"
    )

    # Optional: kill instead of suspend (you can add later)
    SensitiveKillList = @(
        # "obs64","zoom","teams","discord"
    )

    # Device targeting patterns
    CameraNamePatterns = @("Camera","Webcam","UVC","Integrated Camera","IR UVC","USB Video","Windows Studio Effects Camera")
    MicNamePatterns    = @("Microphone","Microphone Array","Mic Array")

    # Network: skip virtual/tunnel/pseudo
    SkipAdapterNamePatterns = @("Loopback","Teredo","isatap","VirtualBox Host-Only","VMware Network Adapter","Npcap","Tailscale")

    # Event logs to capture (best-effort)
    EventLogs = @(
        @{ LogName="System";   Max=250 },
        @{ LogName="Security"; Max=120 },
        @{ LogName="Microsoft-Windows-DeviceSetupManager/Admin"; Max=180 }
    )

    # Verification (trust-but-verify)
    EnableVerification = $true

    # Freeze control (UserSafe)
    MaxSuspendCount = 25        # hard cap; prevents "suspend too much" scenarios
    FreezePlanLogLimit = 60     # how many planned targets to log in detail
    FreezePreferForeground = $true
    FreezePriorityNames    = @("code","firefox","msedge","chrome","brave","discord","slack","telegram","signal")
    # Hardening: freeze "active apps only" (windowed), but always include priority apps
    FreezeActiveAppsOnly = $true

    # Hardening: never suspend these even if they have a window / appear active
    FreezeDenyList = @(
        "textinputhost","sihost","shellexperiencehost","startmenuexperiencehost",
        "searchhost","searchindexer","applicationframehost","runtimebroker","taskhostw",
        "widgets","widgetservice","msedgewebview2",
        "nvidia overlay","nvidia share","nvidiaoverlay","gamebar","gamebarftserver",
        "yourphone","phoneexperiencehost"
    )

}

# -------------------------
# Paths / run folder
# -------------------------
$Root     = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunsRoot = Join-Path $Root "runs"
New-Item -ItemType Directory -Force -Path $RunsRoot | Out-Null

function Get-LatestRunId {
    if (-not (Test-Path $RunsRoot)) { return $null }
    $dirs = @(Get-ChildItem -Path $RunsRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    foreach ($d in $dirs) {
        $sp = Join-Path $d.FullName "state.json"
        if (-not (Test-Path $sp)) { continue }
        try {
            $st = Get-Content $sp -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($st -and $st.mode -eq "Panic" -and (-not $st.dryRun)) { return $d.Name }
        } catch { }
    }
    return $null
}

$NowRunId = (Get-Date).ToString("yyyyMMdd_HHmmss")
if ($Mode -eq "Restore" -and [string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = Get-LatestRunId
    if (-not $RunId) { throw "No prior runs found under: $RunsRoot" }
}

$EffectiveRunId = if ($Mode -eq "Restore") { $RunId } else { $NowRunId }
$OutDir         = Join-Path $RunsRoot $EffectiveRunId
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$ActionsPath = Join-Path $OutDir "actions.jsonl"
$StatePath   = Join-Path $OutDir "state.json"
$ReportPath  = Join-Path $OutDir "report.html"

# -------------------------
# Logging
# -------------------------
function Write-Action {
    param(
        [string]$Step,
        [string]$Action,
        [string]$Target = "",
        [ValidateSet("OK","FAIL","DRYRUN","INFO","WARN")]
        [string]$Result = "OK",
        [string]$Details = ""
    )
    $obj = [ordered]@{
        ts      = (Get-Date).ToString("o")
        mode    = $Mode
        runId   = $EffectiveRunId
        dryRun  = [bool]$DryRun
        step    = $Step
        action  = $Action
        target  = $Target
        result  = $Result
        details = $Details
        version = $Cfg.Version
    }
    ($obj | ConvertTo-Json -Compress) | Add-Content -Path $ActionsPath -Encoding UTF8
}

function Write-Verify {
    param(
        [string]$Action,
        [string]$Target,
        [ValidateSet("OK","FAIL","WARN","INFO")]
        [string]$Result,
        [string]$Details = ""
    )
    Write-Action -Step "verify" -Action $Action -Target $Target -Result $Result -Details $Details
}

# -------------------------
# Admin guard
# -------------------------
function Test-IsAdmin {
    try {
        $wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Assert-Admin {
    if ($DryRun) {
        Write-Action -Step "preflight" -Action "admin_check" -Result "INFO" -Details "DryRun: admin not strictly required."
        return
    }
    if (-not (Test-IsAdmin)) {
        Write-Action -Step "preflight" -Action "admin_check" -Result "FAIL" -Details "Not running as Administrator."
        throw "Please re-run PowerShell as Administrator."
    }
    Write-Action -Step "preflight" -Action "admin_check" -Result "OK" -Details "Running as admin."
}

# -------------------------
# Audio (mute/unmute) via CoreAudio (no external modules)
# -------------------------
$script:AudioTypeLoaded = $false
function Ensure-CoreAudioType {
    if ($script:AudioTypeLoaded) { return }

# If types already exist in this PowerShell session, don't re-add.
if ("CurtainDropAudio.CoreAudio" -as [type]) {
    $script:AudioTypeLoaded = $true
    return
}

$code = @"
using System;
using System.Runtime.InteropServices;

namespace CurtainDropAudio {

  public enum EDataFlow { eRender = 0, eCapture = 1, eAll = 2 }
  public enum ERole { eConsole = 0, eMultimedia = 1, eCommunications = 2 }

  [ComImport]
  [Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
  [TypeLibType(TypeLibTypeFlags.FCanCreate)]
  public class MMDeviceEnumeratorComObject { }

  [ComImport]
  [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IMMDeviceEnumerator {
    int EnumAudioEndpoints(EDataFlow dataFlow, uint dwStateMask, out object ppDevices);
    int GetDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, out IMMDevice ppDevice);
    int GetDevice([MarshalAs(UnmanagedType.LPWStr)] string pwstrId, out IMMDevice ppDevice);
    int RegisterEndpointNotificationCallback(IntPtr pClient);
    int UnregisterEndpointNotificationCallback(IntPtr pClient);
  }

  [ComImport]
  [Guid("D666063F-1587-4E43-81F1-B948E807363F")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IMMDevice {
    int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams,
      [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
  }

  [ComImport]
  [Guid("5CDF2C82-841E-4546-9722-0CF74078229A")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioEndpointVolume {
    int RegisterControlChangeNotify(IntPtr pNotify);
    int UnregisterControlChangeNotify(IntPtr pNotify);
    int GetChannelCount(out uint pnChannelCount);
    int SetMasterVolumeLevel(float fLevelDB, Guid pguidEventContext);
    int SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext);
    int GetMasterVolumeLevel(out float pfLevelDB);
    int GetMasterVolumeLevelScalar(out float pfLevel);
    int SetChannelVolumeLevel(uint nChannel, float fLevelDB, Guid pguidEventContext);
    int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, Guid pguidEventContext);
    int GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
    int GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
    int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext);
    int GetMute(out bool pbMute);
  }

    public static class CoreAudio {
    const int CLSCTX_ALL = 23;

    private static IAudioEndpointVolume GetEndpoint() {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumeratorComObject());
        IMMDevice dev;
        enumerator.GetDefaultAudioEndpoint(EDataFlow.eRender, ERole.eMultimedia, out dev);
        Guid iid = typeof(IAudioEndpointVolume).GUID;
        object obj;
        dev.Activate(ref iid, CLSCTX_ALL, IntPtr.Zero, out obj);
        return (IAudioEndpointVolume)obj;
    }

    public static bool GetMute() {
        var ep = GetEndpoint();
        bool mute;
        ep.GetMute(out mute);
        return mute;
    }

    public static void SetMute(bool mute) {
        var ep = GetEndpoint();
        ep.SetMute(mute, Guid.Empty);
    }

    public static float GetVolumeScalar() {
        var ep = GetEndpoint();
        float v;
        ep.GetMasterVolumeLevelScalar(out v);
        return v;
    }

    public static void SetVolumeScalar(float v) {
        var ep = GetEndpoint();
        ep.SetMasterVolumeLevelScalar(v, Guid.Empty);
    }
    }

}
"@

    Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop | Out-Null
    $script:AudioTypeLoaded = $true
}

function Get-AudioState {
    try {
        Ensure-CoreAudioType
        return [pscustomobject]@{
            mute   = [bool]([CurtainDropAudio.CoreAudio]::GetMute())
            volume = [double]([CurtainDropAudio.CoreAudio]::GetVolumeScalar())
        }
    } catch {
        return $null
    }
}

function Set-AudioMute {
    param([bool]$Mute)

    if ($DryRun) {
        Write-Action -Step "audio" -Action "SetMute" -Target "default_render" -Result "DRYRUN" -Details ("Mute=" + $Mute)
        return
    }

    try {
        Ensure-CoreAudioType
        [CurtainDropAudio.CoreAudio]::SetMute([bool]$Mute)
        Write-Action -Step "audio" -Action "SetMute" -Target "default_render" -Result "OK" -Details ("Mute=" + $Mute)
    } catch {
        Write-Action -Step "audio" -Action "SetMute" -Target "default_render" -Result "WARN" -Details $_.Exception.Message
    }
}

function Set-AudioVolumeScalar {
    param([double]$Volume)

    if ($DryRun) {
        Write-Action -Step "audio" -Action "SetVolumeScalar" -Target "default_render" -Result "DRYRUN" -Details ("Volume=" + $Volume)
        return
    }

    try {
        Ensure-CoreAudioType
        # clamp
        $v = [double]$Volume
        if ($v -lt 0) { $v = 0 }
        if ($v -gt 1) { $v = 1 }

        [CurtainDropAudio.CoreAudio]::SetVolumeScalar([single]$v)
        Write-Action -Step "audio" -Action "SetVolumeScalar" -Target "default_render" -Result "OK" -Details ("Volume=" + $v)
    } catch {
        Write-Action -Step "audio" -Action "SetVolumeScalar" -Target "default_render" -Result "WARN" -Details $_.Exception.Message
    }
}

function Verify-AudioMute {
    param([bool]$ExpectedMute)

    try {
        $st = Get-AudioState
        if (-not $st) {
            Write-Verify -Action "audio_mute" -Target "default_render" -Result "WARN" -Details "Could not read audio state."
            return $false
        }

        $m = [bool]$st.mute
        if ($m -eq $ExpectedMute) {
            Write-Verify -Action "audio_mute" -Target "default_render" -Result "OK" -Details ("Mute=" + $m)
            return $true
        }

        Write-Verify -Action "audio_mute" -Target "default_render" -Result "FAIL" -Details ("Expected Mute=" + $ExpectedMute + "; Got=" + $m)
        return $false
    } catch {
        Write-Verify -Action "audio_mute" -Target "default_render" -Result "WARN" -Details $_.Exception.Message
        return $false
    }
}

function Verify-AudioVolume {
    param([double]$ExpectedVolume)

    try {
        $st = Get-AudioState
        if (-not $st) {
            Write-Verify -Action "audio_volume" -Target "default_render" -Result "WARN" -Details "Could not read audio state."
            return $false
        }

        $v = [double]$st.volume
        $exp = [double]$ExpectedVolume

        # tolerance (CoreAudio scalar can jitter slightly)
        if ([Math]::Abs($v - $exp) -le 0.03) {
            Write-Verify -Action "audio_volume" -Target "default_render" -Result "OK" -Details ("Volume=" + $v)
            return $true
        }

        Write-Verify -Action "audio_volume" -Target "default_render" -Result "WARN" -Details ("Expected~" + $exp + "; Got=" + $v)
        return $false
    } catch {
        Write-Verify -Action "audio_volume" -Target "default_render" -Result "WARN" -Details $_.Exception.Message
        return $false
    }
}

# -------------------------
# Snapshot state (what WE changed)
# -------------------------
function Save-State {
    param(
        [array]$DisabledDevices,
        [array]$DisabledAdapters,
        [array]$SuspendedPids,
        [object]$AudioBefore
    )

    # Normalize arrays so state.json never stores null (prevents @($null).Count == 1)
    $ddOut = @()
    if ($null -ne $DisabledDevices)  { $ddOut = @($DisabledDevices)  | Where-Object { $_ -ne $null } }

    $daOut = @()
    if ($null -ne $DisabledAdapters) { $daOut = @($DisabledAdapters) | Where-Object { $_ -ne $null } }

    $spOut = @()
    if ($null -ne $SuspendedPids)    { $spOut = @($SuspendedPids)    | Where-Object { $_ -ne $null } }

    $state = [ordered]@{
        ts = (Get-Date).ToString("o")
        user = $env:USERNAME
        computer = $env:COMPUTERNAME
        version = $Cfg.Version
        mode = $Mode
        dryRun = [bool]$DryRun

        disabled_devices = $ddOut
        disabled_adapters = $daOut
        suspended_pids = $spOut

        audio_before = $AudioBefore
    }

    $state | ConvertTo-Json -Depth 8 | Set-Content -Path $StatePath -Encoding UTF8
    Write-Action -Step "snapshot" -Action "save_state" -Result "OK" -Details "Saved: $StatePath"
}

function Load-State {
    if (-not (Test-Path $StatePath)) { return $null }
    try {
        return (Get-Content $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch { return $null }
}

# -------------------------
# PnP device ops (STRICT classes only)
# -------------------------
function Get-TargetPnpDevices {
    param(
        [string[]]$Classes,
        [string[]]$NamePatterns
    )

    $all = @()
    try { $all = @(Get-PnpDevice -PresentOnly -ErrorAction Stop) } catch { return @() }

    $targets = @()
    foreach ($d in $all) {
        $cls = [string]$d.Class
        if ($Classes -notcontains $cls) { continue }

        $fn = [string]$d.FriendlyName
        if ([string]::IsNullOrWhiteSpace($fn)) { continue }

        $matched = $false
        foreach ($pat in $NamePatterns) {
            if ($fn -like ("*" + $pat + "*")) { $matched = $true; break }
        }
        if (-not $matched) { continue }

        $targets += $d
    }
    return $targets
}

function Disable-PnpTargets {
    param([array]$Devices)

    $disabled = @()
    foreach ($d in @($Devices)) {
        $id = [string]$d.InstanceId
        $name = [string]$d.FriendlyName
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        if ($DryRun) {
            Write-Action -Step "devices" -Action "Disable-PnpDevice" -Target $name -Result "DRYRUN" -Details $id
            $disabled += [pscustomobject]@{ FriendlyName=$name; InstanceId=$id }
            continue
        }

        try {
            Disable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Action -Step "devices" -Action "Disable-PnpDevice" -Target $name -Result "OK" -Details $id
            $disabled += [pscustomobject]@{ FriendlyName=$name; InstanceId=$id }
        } catch {
            Write-Action -Step "devices" -Action "Disable-PnpDevice" -Target $name -Result "WARN" -Details $_.Exception.Message
        }
    }
    return $disabled
}

function Enable-PnpByInstanceIds {
    param([array]$DevicesFromState)

    foreach ($d in @($DevicesFromState)) {
        $id = [string]$d.InstanceId
        $name = [string]$d.FriendlyName
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        if ($DryRun) {
            Write-Action -Step "devices" -Action "Enable-PnpDevice" -Target $name -Result "DRYRUN" -Details $id
            continue
        }

        try {
            Enable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Action -Step "devices" -Action "Enable-PnpDevice" -Target $name -Result "OK" -Details $id
        } catch {
            Write-Action -Step "devices" -Action "Enable-PnpDevice" -Target $name -Result "WARN" -Details $_.Exception.Message
        }
    }
}

function Get-PnpDisableCode {
    param([string]$InstanceId)

    try {
        # small N; OK to enumerate
        $ent = Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
               Where-Object { $_.DeviceID -eq $InstanceId } |
               Select-Object -First 1

        if (-not $ent) { return $null }
        return [int]$ent.ConfigManagerErrorCode
    } catch {
        return $null
    }
}

function Verify-DeviceState {
    param(
        [string]$FriendlyName,
        [string]$InstanceId,
        [ValidateSet("Disabled","Enabled")]
        [string]$Expected
    )

    $code = Get-PnpDisableCode -InstanceId $InstanceId
    if ($null -eq $code) {
        Write-Verify -Action "device_state" -Target $FriendlyName -Result "WARN" -Details ("Could not query Win32_PnPEntity for: " + $InstanceId)
        return $false
    }

    # ConfigManagerErrorCode: 0 = OK, 22 = Disabled
    if ($Expected -eq "Enabled") {
        if ($code -eq 0) {
            Write-Verify -Action "device_state" -Target $FriendlyName -Result "OK" -Details "Enabled (Code=0)"
            return $true
        }
        Write-Verify -Action "device_state" -Target $FriendlyName -Result "FAIL" -Details ("Expected Enabled; Code=" + $code)
        return $false
    } else {
        if ($code -eq 22) {
            Write-Verify -Action "device_state" -Target $FriendlyName -Result "OK" -Details "Disabled (Code=22)"
            return $true
        }
        Write-Verify -Action "device_state" -Target $FriendlyName -Result "FAIL" -Details ("Expected Disabled; Code=" + $code)
        return $false
    }
}

function Verify-DevicesFromState {
    param(
        [array]$Devices,
        [ValidateSet("Disabled","Enabled")]
        [string]$Expected
    )

    $allOk = $true
    foreach ($d in @($Devices)) {
        $id = [string]$d.InstanceId
        $name = [string]$d.FriendlyName
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $ok = Verify-DeviceState -FriendlyName $name -InstanceId $id -Expected $Expected
        if (-not $ok) { $allOk = $false }
    }
    return $allOk
}

# -------------------------
# Network ops (enable/disable only what we touch)
# -------------------------
function Test-SkipAdapterName {
    param([string]$Name)
    foreach ($p in $Cfg.SkipAdapterNamePatterns) {
        if ($Name -like ("*" + $p + "*")) { return $true }
    }
    return $false
}

function Disable-ActiveAdapters {
    $disabled = @()
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -ErrorAction Stop) } catch { $adapters = @() }

    foreach ($a in $adapters) {
        $name = [string]$a.Name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if (Test-SkipAdapterName -Name $name) { continue }
        if ([string]$a.AdminStatus -ne "Up") { continue }

        if ($DryRun) {
            Write-Action -Step "network" -Action "Disable-NetAdapter" -Target $name -Result "DRYRUN" -Details ""
            $disabled += $name
            continue
        }

        try {
            Disable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Action -Step "network" -Action "Disable-NetAdapter" -Target $name -Result "OK" -Details ""
            $disabled += $name
        } catch {
            Write-Action -Step "network" -Action "Disable-NetAdapter" -Target $name -Result "WARN" -Details $_.Exception.Message
        }
    }
    return $disabled
}

function Enable-AdaptersByName {
    param([string[]]$Names)
    foreach ($name in @($Names)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        if ($DryRun) {
            Write-Action -Step "network" -Action "Enable-NetAdapter" -Target $name -Result "DRYRUN" -Details ""
            continue
        }

        try {
            Enable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Action -Step "network" -Action "Enable-NetAdapter" -Target $name -Result "OK" -Details ""
        } catch {
            Write-Action -Step "network" -Action "Enable-NetAdapter" -Target $name -Result "WARN" -Details $_.Exception.Message
        }
    }
}

function Verify-AdapterState {
    param(
        [string]$Name,
        [ValidateSet("Up","NotUp")]
        [string]$Expected
    )

    try {
        $a = Get-NetAdapter -Name $Name -ErrorAction Stop

        # Use AdminStatus (enabled/disabled) instead of Status (connected/disconnected)
        $admin = [string]$a.AdminStatus  # Up / Down
        $status = [string]$a.Status      # Up / Disconnected / Disabled / etc.

        if ($Expected -eq "Up") {
            if ($admin -eq "Up") {
                Write-Verify -Action "adapter_state" -Target $Name -Result "OK" -Details ("AdminStatus=Up; Status=" + $status)
                return $true
            }
            Write-Verify -Action "adapter_state" -Target $Name -Result "FAIL" -Details ("Expected Enabled; AdminStatus=" + $admin + "; Status=" + $status)
            return $false
        } else {
            if ($admin -ne "Up") {
                Write-Verify -Action "adapter_state" -Target $Name -Result "OK" -Details ("AdminStatus=" + $admin + "; Status=" + $status)
                return $true
            }
            Write-Verify -Action "adapter_state" -Target $Name -Result "FAIL" -Details ("Expected Disabled; AdminStatus=Up; Status=" + $status)
            return $false
        }
    } catch {
        Write-Verify -Action "adapter_state" -Target $Name -Result "WARN" -Details $_.Exception.Message
        return $false
    }
}

function Verify-AdaptersByName {
    param(
        [string[]]$Names,
        [ValidateSet("Up","NotUp")]
        [string]$Expected
    )

    $allOk = $true
    foreach ($n in @($Names)) {
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        $ok = Verify-AdapterState -Name $n -Expected $Expected
        if (-not $ok) { $allOk = $false }
    }
    return $allOk
}

# -------------------------
# Process freeze (UserSafe only)
# -------------------------
$PsSuspend = Join-Path $Root "pssuspend.exe"
if (-not (Test-Path $PsSuspend)) {
    $PsSuspend = Join-Path (Join-Path $Root "tools") "pssuspend.exe"
}

function Assert-PsSuspend {
    if ($FreezeMode -eq "Off") { return $false }
    if (-not (Test-Path $PsSuspend)) {
        Write-Action -Step "preflight" -Action "pssuspend_check" -Result "WARN" -Details ("Missing pssuspend.exe at: " + $PsSuspend)
        return $false
    }
    Write-Action -Step "preflight" -Action "pssuspend_check" -Result "OK" -Details $PsSuspend
    return $true
}

function Get-UserOwnedSessionProcesses {
    # Use CIM so we can read Owner + SessionId in one pass (avoid suspending system services)
    $sessId = (Get-Process -Id $PID).SessionId
    $me = $env:USERNAME

    $rows = @()
    try {
        $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.SessionId -eq $sessId })
    } catch {
        # Fallback: at least filter by session using Get-Process
        $rows = @()
    }

    $pids = New-Object System.Collections.Generic.List[int]
    foreach ($r in $rows) {
        try {
            $owner = $null
            $o = Invoke-CimMethod -InputObject $r -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($o -and $o.ReturnValue -eq 0) { $owner = [string]$o.User }
            if ($owner -ne $me) { continue }
            $pids.Add([int]$r.ProcessId) | Out-Null
        } catch { }
    }

    if ($pids.Count -eq 0) {
        # Fallback: session-only (less safe than owner filter, but still better than global)
        $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sessId })
        foreach ($p in $procs) {
            try { $pids.Add([int]$p.Id) | Out-Null } catch { }
        }
    }

    return @($pids)
}

function Suspend-UserSafeProcesses {
    if ($FreezeMode -eq "Off") {
        Write-Action -Step "freeze" -Action "suspend" -Result "INFO" -Details "FreezeMode=Off"
        return @()
    }
    if (-not (Assert-PsSuspend)) {
        Write-Action -Step "freeze" -Action "suspend" -Result "WARN" -Details "pssuspend missing; skipping suspend."
        return @()
    }

    $allow = @{}
    foreach ($n in $Cfg.ProcessNameAllowList) {
        if (-not [string]::IsNullOrWhiteSpace($n)) { $allow[$n.ToLowerInvariant()] = $true }
    }
    # Normalize deny-list to lowercase hash for reliable matching
    $deny = @{}
    if ($Cfg.ContainsKey("FreezeDenyList") -and $Cfg.FreezeDenyList) {
        foreach ($d in @($Cfg.FreezeDenyList)) {
            if (-not [string]::IsNullOrWhiteSpace($d)) { $deny[$d.ToLowerInvariant()] = $true }
        }
    }

    $candidatePids = @(Get-UserOwnedSessionProcesses)
    $suspended = @()

        # Build a "freeze plan" (controlled visibility) before executing
    # Priority-first so critical apps always get suspended even under cap.
    $prio = @{}
    if ($Cfg.ContainsKey("FreezePriorityNames") -and $Cfg.FreezePriorityNames) {
        $i = 0
        foreach ($n in @($Cfg.FreezePriorityNames)) {
            if (-not [string]::IsNullOrWhiteSpace($n)) {
                $prio[$n.ToLowerInvariant()] = (1000 - $i)  # higher is better
                $i++
            }
        }
    }

    $planObjs = @()
    foreach ($pid2 in $candidatePids) {
        if ($pid2 -eq $PID) { continue }

        $p = $null
        try { $p = Get-Process -Id $pid2 -ErrorAction Stop } catch { continue }

        $name = ""
        try { $name = [string]$p.ProcessName } catch { $name = "" }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $lname = $name.ToLowerInvariant()

        # Hard safety nets
        if ($allow.ContainsKey($lname)) { continue }
        if ($lname -in @("winlogon","csrss","services","svchost","lsass","system","registry","secure system","smss","wininit","dwm")) { continue }

        # Deny-list (UX helpers / overlays / brokers) - never suspend
        if ($deny.ContainsKey($lname)) { continue }


        $hasWindow = $false
        $ws = 0
        try { $hasWindow = ($p.MainWindowHandle -ne 0) } catch { }
        try { $ws = [int64]$p.WorkingSet64 } catch { }

        $isPriority = $false
        if ($prio.ContainsKey($lname)) { $isPriority = $true }

        # Hardening: "active apps only"
        # - If enabled: only suspend windowed processes, except priority apps (include helpers too)
        if ($Cfg.ContainsKey("FreezeActiveAppsOnly") -and $Cfg.FreezeActiveAppsOnly) {
            if (-not $hasWindow -and -not $isPriority) { continue }
        }

        # Scoring
        $score = 0
        if ($isPriority) { $score = [int]$prio[$lname] }  # priority dominates
        if ($Cfg.ContainsKey("FreezePreferForeground") -and $Cfg.FreezePreferForeground -and $hasWindow) { $score += 200 }

        $planObjs += [pscustomobject]@{
            Name      = $name
            Pid       = [int]$pid2
            Score     = [int]$score
            HasWindow = [bool]$hasWindow
            WS        = [int64]$ws
        }
    }

    # Order: priority score desc, foreground first, then larger working set
    $planObjs = @($planObjs | Sort-Object -Property @{Expression="Score";Descending=$true}, @{Expression="HasWindow";Descending=$true}, @{Expression="WS";Descending=$true})

    $totalPlan = @($planObjs).Count
    Write-Action -Step "freeze" -Action "freeze_plan" -Result "INFO" -Details ("PlannedSuspendCount=" + $totalPlan)

    $limit = [int]$Cfg.MaxSuspendCount
    if ($totalPlan -gt $limit) {
        Write-Action -Step "freeze" -Action "freeze_plan" -Result "WARN" -Details ("PlannedSuspendCount exceeds cap (" + $limit + "). Suspending top " + $limit + " after prioritization.")
        $planObjs = @($planObjs | Select-Object -First $limit)
    }

    $plan = @()
    foreach ($o in $planObjs) { $plan += ($o.Name + "#" + $o.Pid) }

    # Log first N planned targets (controlled)
    $n = [int]$Cfg.FreezePlanLogLimit
    $sample = @($plan | Select-Object -First $n)
    if (@($sample).Count -gt 0) {
        Write-Action -Step "freeze" -Action "freeze_plan_sample" -Result "INFO" -Details (($sample -join ", "))
    }

    # Trust-but-verify: ensure priority apps are included when present
    if ($Cfg.ContainsKey("FreezePriorityNames") -and $Cfg.FreezePriorityNames) {
        foreach ($must in @($Cfg.FreezePriorityNames)) {
            $m = [string]$must
            if ([string]::IsNullOrWhiteSpace($m)) { continue }
            $present = $false
            foreach ($e in $plan) { if ($e.ToLowerInvariant().StartsWith($m.ToLowerInvariant() + "#")) { $present = $true; break } }
            if (-not $present) {
                Write-Action -Step "freeze" -Action "freeze_priority_check" -Result "WARN" -Details ("Priority target not in plan (may not be running or exceeded cap before prioritization): " + $m)
            }
        }
    }

        foreach ($entry in $plan) {
        $parts = $entry.Split("#")
        if ($parts.Count -lt 2) { continue }

        $name = $parts[0]
        $pid2 = [int]$parts[1]
        if (-not $pid2) { continue }
        if ($pid2 -eq $PID) { continue }

        if ($DryRun) {
            Write-Action -Step "freeze" -Action "pssuspend" -Target ($name + "#" + $pid2) -Result "DRYRUN"
            continue
        }

        try {
            & $PsSuspend -accepteula -nobanner $pid2 2>$null | Out-Null
            Write-Action -Step "freeze" -Action "pssuspend" -Target ($name + "#" + $pid2) -Result "OK"
            $suspended += $pid2
        } catch {
            Write-Action -Step "freeze" -Action "pssuspend" -Target ($name + "#" + $pid2) -Result "WARN" -Details $_.Exception.Message
        }
    }

    Write-Action -Step "freeze" -Action "suspend_summary" -Result "INFO" -Details ("SuspendedCount=" + @($suspended).Count)

    return $suspended
}

function Resume-SuspendedPids {
    param([int[]]$Pids)
    if (-not (Test-Path $PsSuspend)) {
        Write-Action -Step "freeze" -Action "resume" -Result "WARN" -Details "pssuspend missing; cannot resume."
        return
    }

    foreach ($pid2 in @($Pids)) {
        if (-not $pid2) { continue }
        if ($pid2 -eq $PID) { continue }

        $name = "pid"
        try {
            $p = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
            if ($p) { $name = $p.ProcessName }
        } catch { }

        if ($DryRun) {
            Write-Action -Step "freeze" -Action "pssuspend -r" -Target ($name + "#" + $pid2) -Result "DRYRUN"
            continue
        }

        try {
            & $PsSuspend -accepteula -nobanner -r $pid2 2>$null | Out-Null
            Write-Action -Step "freeze" -Action "pssuspend -r" -Target ($name + "#" + $pid2) -Result "OK"
        } catch {
            Write-Action -Step "freeze" -Action "pssuspend -r" -Target ($name + "#" + $pid2) -Result "WARN" -Details $_.Exception.Message
        }
    }
}

# -------------------------
# Event logs
# -------------------------
function Get-RecentEventBundles {
    $since = (Get-Date).AddMinutes(-60)
    $bundles = @()

    foreach ($spec in $Cfg.EventLogs) {
        $log = [string]$spec.LogName
        $max = [int]$spec.Max
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$since } -ErrorAction Stop |
                  Select-Object -First $max TimeCreated, Id, LevelDisplayName, ProviderName, Message

            $count = @($ev).Count
            Write-Action -Step "logs" -Action "Get-WinEvent" -Target $log -Result "OK" -Details ("Captured=" + $count)
            $bundles += [pscustomobject]@{ LogName=$log; Events=$ev }
        } catch {
            Write-Action -Step "logs" -Action "Get-WinEvent" -Target $log -Result "WARN" -Details $_.Exception.Message
            $bundles += [pscustomobject]@{ LogName=$log; Events=@() }
        }
    }

    return $bundles
}

# -------------------------
# HTML report (layered + filter)
# -------------------------
function New-Report {
    param([array]$EventBundles)

    function HtmlEnc {
        param([object]$s)
        return [System.Net.WebUtility]::HtmlEncode([string]$s)
    }

    $actions = @()
    if (Test-Path $ActionsPath) {
        $actions = Get-Content $ActionsPath -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ -ne $null }
    }

    $stateObj = $null
    if (Test-Path $StatePath) {
        try { $stateObj = Get-Content $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $stateObj = $null }
    }

    # True target counts (from state.json), not action row counts
    $deviceTargets  = 0
    $adapterTargets = 0
    $procTargets    = 0
    if ($stateObj) {
        try { $deviceTargets  = @($stateObj.disabled_devices).Count } catch {}
        try { $adapterTargets = @($stateObj.disabled_adapters).Count } catch {}
        try { $procTargets = @($stateObj.suspended_pids | Where-Object { $_ -ne $null }).Count } catch {}
    }

    $summary = [ordered]@{
        Timestamp  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Mode       = $Mode
        RunId      = $EffectiveRunId
        DryRun     = [bool]$DryRun
        User       = $env:USERNAME
        Computer   = $env:COMPUTERNAME
        Version    = $Cfg.Version
        OutputDir  = $OutDir
        FreezeMode = $FreezeMode
    }

    # Category counters (for quick signal)
    $counts = @{
        all     = @($actions).Count
        devices = 0
        network = 0
        audio   = 0
        freeze  = 0
        logs    = 0
        verify  = 0
        fatal   = 0
    }

    foreach ($a in @($actions)) {
        $step = ([string]$a.step)
        if ($step -like "devices*") { $counts.devices++ }
        elseif ($step -like "network*") { $counts.network++ }
        elseif ($step -like "audio*") { $counts.audio++ }
        elseif ($step -like "freeze*") { $counts.freeze++ }
        elseif ($step -like "logs*") { $counts.logs++ }
        elseif ($step -like "verify*") { $counts.verify++ }
        elseif ($step -like "fatal*") { $counts.fatal++ }
    }

    $html = New-Object System.Collections.Generic.List[string]

    $title = "CurtainDrop Report - " + $EffectiveRunId
    $sub   = ("Run {0} | Mode {1} | DryRun {2} | FreezeMode {3}" -f $EffectiveRunId, $Mode, $DryRun, $FreezeMode)

    $html.Add("<!doctype html>") | Out-Null
    $html.Add("<html lang='en'><head><meta charset='utf-8'/>") | Out-Null
    $html.Add("<meta name='viewport' content='width=device-width, initial-scale=1'/>") | Out-Null
    $html.Add("<title>$(HtmlEnc $title)</title>") | Out-Null

    $html.Add(@"
<style>
  :root{
    --bg:#fbfbfc; --card:#ffffff; --ink:#111827; --muted:#6b7280; --line:#e5e7eb;
    --ok:#0a7a0a; --fail:#b00020; --warn:#b26a00; --info:#0b57d0; --dry:#6b7280;
  }
  body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,system-ui}
  .wrap{max-width:none;margin:0;padding:18px}
  h1{margin:0;font-size:22px}
  .sub{margin:6px 0 14px 0;color:var(--muted);font-size:13px}
  .bar{
    position:sticky;top:0;background:rgba(251,251,252,0.92);backdrop-filter:saturate(180%) blur(8px);
    border-bottom:1px solid var(--line);padding:10px 0;margin:0 0 14px 0;z-index:10;
  }
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .pill{
    border:1px solid var(--line);background:var(--card);padding:8px 10px;border-radius:999px;
    cursor:pointer;font-size:13px;user-select:none
  }
  .pill.active{border-color:var(--ink);background:var(--ink);color:#fff}
  .search{
    padding:8px 10px;border:1px solid var(--line);border-radius:999px;min-width:260px;
    background:var(--card);margin-left:auto
  }
  .grid{display:grid;grid-template-columns:1.6fr 1fr;gap:14px;align-items:start}
  .card{
    border:1px solid var(--line);border-radius:14px;background:var(--card);
    box-shadow:0 1px 4px rgba(0,0,0,0.05);padding:14px
  }
  .kvs{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
  .kv{border:1px solid var(--line);border-radius:12px;padding:10px}
  .kv .k{color:var(--muted);font-size:12px}
  .kv .v{font-weight:600;margin-top:2px}
  table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
  th,td{border:1px solid var(--line);padding:8px;vertical-align:top}
  th{background:#f3f4f6}
  .mono{font-family:Consolas,ui-monospace,monospace;font-size:12px;white-space:pre-wrap}
  .OK{color:var(--ok);font-weight:700}
  .FAIL{color:var(--fail);font-weight:800}
  .WARN{color:var(--warn);font-weight:800}
  .INFO{color:var(--info);font-weight:800}
  .DRYRUN{color:var(--dry);font-weight:800}
  details{border:1px solid var(--line);border-radius:12px;padding:10px;margin-top:10px;background:#fff}
  summary{cursor:pointer;font-weight:700}
  .foot{margin-top:14px;color:var(--muted);font-size:12px}
</style>

<script>
  const state = { cat: "all", q: "" };

  function applyFilters(){
    const rows = document.querySelectorAll("[data-cat][data-text]");
    rows.forEach(r=>{
      const catOk = (state.cat === "all") || (r.getAttribute("data-cat") === state.cat);
      const txt = (r.getAttribute("data-text") || "");
      const qOk = !state.q || txt.includes(state.q);
      r.style.display = (catOk && qOk) ? "" : "none";
    });
  }

  function setFilter(cat){
    state.cat = cat;
    document.querySelectorAll(".pill").forEach(p=>p.classList.remove("active"));
    const el = document.getElementById("pill_"+cat);
    if (el) el.classList.add("active");
    applyFilters();
  }

  function setSearch(v){
    state.q = (v || "").toLowerCase();
    applyFilters();
  }

  window.addEventListener("DOMContentLoaded", ()=>{ applyFilters(); });
</script>
</head><body>
"@) | Out-Null

    $html.Add("<div class='wrap'>") | Out-Null
    $html.Add("<h1>CurtainDrop</h1>") | Out-Null
    $html.Add("<div class='sub'>$(HtmlEnc $sub)</div>") | Out-Null

    $html.Add(@"
<div class='bar'>
  <div class='row'>
    <div id='pill_all' class='pill active' onclick="setFilter('all')">All</div>
    <div id='pill_devices' class='pill' onclick="setFilter('devices')">Cam/Mic</div>
    <div id='pill_network' class='pill' onclick="setFilter('network')">Network</div>
    <div id='pill_audio' class='pill' onclick="setFilter('audio')">Audio</div>
    <div id='pill_freeze' class='pill' onclick="setFilter('freeze')">Processes</div>
    <div id='pill_logs' class='pill' onclick="setFilter('logs')">Logs</div>
    <input class='search' placeholder='Search actions...' oninput="setSearch(this.value)"/>
  </div>
</div>
"@) | Out-Null

    $html.Add("<div class='grid'>") | Out-Null

    # LEFT: Actions
    $html.Add("<div class='card'>") | Out-Null
    $html.Add("<div style='display:flex;gap:10px;align-items:baseline;flex-wrap:wrap'>") | Out-Null
    $html.Add("<h2 style='margin:0;font-size:16px'>Actions</h2>") | Out-Null
    $html.Add("<div class='sub' style='margin:0'>Total: $(HtmlEnc $counts.all) | Verify: $(HtmlEnc $counts.verify) | Fatal: $(HtmlEnc $counts.fatal)</div>") | Out-Null
    $html.Add("</div>") | Out-Null

    $html.Add("<table><tr><th>Time</th><th>Step</th><th>Action</th><th>Target</th><th>Result</th><th>Details</th></tr>") | Out-Null

    foreach ($a in @($actions)) {
        $step = [string]$a.step
        $cat = "all"
        if ($step -like "devices*") { $cat = "devices" }
        elseif ($step -like "network*") { $cat = "network" }
        elseif ($step -like "audio*") { $cat = "audio" }
        elseif ($step -like "freeze*") { $cat = "freeze" }
        elseif ($step -like "logs*") { $cat = "logs" }

        $t      = [string]$a.ts
        $act    = [string]$a.action
        $target = [string]$a.target
        $res    = [string]$a.result
        $det    = [string]$a.details

        $text = (($t + " " + $step + " " + $act + " " + $target + " " + $res + " " + $det).ToLowerInvariant())

        $html.Add(("<tr data-cat='{0}' data-text='{1}'>" -f (HtmlEnc $cat), (HtmlEnc $text))) | Out-Null
        $html.Add(("<td class='mono'>{0}</td>" -f (HtmlEnc $t))) | Out-Null
        $html.Add(("<td>{0}</td>" -f (HtmlEnc $step))) | Out-Null
        $html.Add(("<td>{0}</td>" -f (HtmlEnc $act))) | Out-Null
        $html.Add(("<td>{0}</td>" -f (HtmlEnc $target))) | Out-Null
        $html.Add(("<td class='{0}'>{1}</td>" -f (HtmlEnc $res), (HtmlEnc $res))) | Out-Null
        $html.Add(("<td class='mono'>{0}</td>" -f (HtmlEnc $det))) | Out-Null

        $html.Add("</tr>") | Out-Null
    }

    $html.Add("</table>") | Out-Null
    $html.Add("</div>") | Out-Null

    # RIGHT: Summary + State + Logs
    $html.Add("<div>") | Out-Null

    $html.Add("<div class='card'>") | Out-Null
    $html.Add("<h2 style='margin:0 0 8px 0;font-size:16px'>Summary</h2>") | Out-Null
    $html.Add("<div class='kvs'>") | Out-Null
    $html.Add(("<div class='kv'><div class='k'>RunId</div><div class='v'>{0}</div></div>" -f (HtmlEnc $EffectiveRunId))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>Mode</div><div class='v'>{0}</div></div>" -f (HtmlEnc $Mode))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>DryRun</div><div class='v'>{0}</div></div>" -f (HtmlEnc ([bool]$DryRun)))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>FreezeMode</div><div class='v'>{0}</div></div>" -f (HtmlEnc $FreezeMode))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>User</div><div class='v'>{0}</div></div>" -f (HtmlEnc $env:USERNAME))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>Computer</div><div class='v'>{0}</div></div>" -f (HtmlEnc $env:COMPUTERNAME))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>Cam/Mic Targets</div><div class='v'>{0}</div></div>" -f (HtmlEnc $deviceTargets))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>Network Targets</div><div class='v'>{0}</div></div>" -f (HtmlEnc $adapterTargets))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>Audio Actions</div><div class='v'>{0}</div></div>" -f (HtmlEnc $counts.audio))) | Out-Null
    $html.Add(("<div class='kv'><div class='k'>Processes Frozen</div><div class='v'>{0}</div></div>" -f (HtmlEnc $procTargets))) | Out-Null
    $html.Add("</div>") | Out-Null

    $sumJson = ($summary | ConvertTo-Json -Depth 6)
    $html.Add("<details><summary>Raw summary JSON</summary><div class='mono'>$(HtmlEnc $sumJson)</div></details>") | Out-Null
    $html.Add("</div>") | Out-Null

    if ($stateObj) {
        $stJson = ($stateObj | ConvertTo-Json -Depth 8)
        $html.Add("<div class='card'>") | Out-Null
        $html.Add("<h2 style='margin:0 0 8px 0;font-size:16px'>State (what CurtainDrop changed)</h2>") | Out-Null
        $html.Add("<div class='mono'>$(HtmlEnc $stJson)</div>") | Out-Null
        $html.Add("</div>") | Out-Null
    } else {
        $html.Add("<div class='card'><h2 style='margin:0;font-size:16px'>State</h2><div class='sub'>No state.json loaded.</div></div>") | Out-Null
    }

    $html.Add("<div class='card'>") | Out-Null
    $html.Add("<h2 style='margin:0 0 8px 0;font-size:16px'>Event logs (last 60 min)</h2>") | Out-Null

    foreach ($b in @($EventBundles)) {
        $ln  = [string]$b.LogName
        $evs = @($b.Events)

        $html.Add("<details>") | Out-Null
        $html.Add(("<summary>{0} (events: {1})</summary>" -f (HtmlEnc $ln), (HtmlEnc @($evs).Count))) | Out-Null

        if (@($evs).Count -eq 0) {
            $html.Add("<div class='sub'>No events captured.</div>") | Out-Null
        } else {
            $html.Add("<table><tr><th>Time</th><th>Id</th><th>Level</th><th>Provider</th><th>Message</th></tr>") | Out-Null
            foreach ($e in @($evs)) {
                $msg = [string]$e.Message
                if ($msg.Length -gt 900) { $msg = $msg.Substring(0,900) + " ..." }

                $html.Add("<tr>") | Out-Null
                $html.Add(("<td class='mono'>{0}</td>" -f (HtmlEnc $e.TimeCreated))) | Out-Null
                $html.Add(("<td>{0}</td>" -f (HtmlEnc $e.Id))) | Out-Null
                $html.Add(("<td>{0}</td>" -f (HtmlEnc $e.LevelDisplayName))) | Out-Null
                $html.Add(("<td>{0}</td>" -f (HtmlEnc $e.ProviderName))) | Out-Null
                $html.Add(("<td class='mono'>{0}</td>" -f (HtmlEnc $msg))) | Out-Null
                $html.Add("</tr>") | Out-Null
            }
            $html.Add("</table>") | Out-Null
        }

        $html.Add("</details>") | Out-Null
    }

    $html.Add("<div class='foot'>Output: $(HtmlEnc $OutDir) | Report: $(HtmlEnc  $ReportPath) | Actions: $(HtmlEnc $ActionsPath)</div>") | Out-Null
    $html.Add("</div>") | Out-Null

    $html.Add("</div>") | Out-Null # right col
    $html.Add("</div>") | Out-Null # grid
    $html.Add("</div>") | Out-Null # wrap
    $html.Add("</body></html>") | Out-Null

    $htmlText = ($html -join "`r`n")
    Set-Content -Path $ReportPath -Value $htmlText -Encoding UTF8
    Write-Action -Step "report" -Action "write_html" -Target $ReportPath -Result "OK" -Details ""
}


function Open-Report {
    if ($DryRun) {
        Write-Action -Step "report" -Action "open" -Target $ReportPath -Result "DRYRUN" -Details ""
        return
    }
    try {
        Start-Process $ReportPath | Out-Null
        Write-Action -Step "report" -Action "open" -Target $ReportPath -Result "OK" -Details ""
    } catch {
        Write-Action -Step "report" -Action "open" -Target $ReportPath -Result "WARN" -Details $_.Exception.Message
    }
}

# -------------------------
# Main
# -------------------------
try {
    Assert-Admin

    if ($Mode -eq "Panic") {
        # Capture audio-before so Restore can bring it back
        $audioBefore = Get-AudioState
        if ($audioBefore) {
            Write-Action -Step "audio" -Action "audio_before" -Result "OK" -Details (($audioBefore | ConvertTo-Json -Compress))
        } else {
            Write-Action -Step "audio" -Action "audio_before" -Result "WARN" -Details "Could not read CoreAudio state."
        }

        # 1) Mute speakers (optional but safe)
        Set-AudioMute -Mute $true

        # 2) Disable camera/mic (STRICT class filter)
        $cams = Get-TargetPnpDevices -Classes @("Camera","Image") -NamePatterns $Cfg.CameraNamePatterns
        $mics = Get-TargetPnpDevices -Classes @("AudioEndpoint") -NamePatterns $Cfg.MicNamePatterns

        $disabledDevices = @()
        $disabledDevices += Disable-PnpTargets -Devices $cams
        $disabledDevices += Disable-PnpTargets -Devices $mics

        # 3) Disable active network adapters
        $disabledAdapters = Disable-ActiveAdapters

        if ($Cfg.EnableVerification -and -not $DryRun) {
            # Verify audio mute applied (best-effort)
            Verify-AudioMute -ExpectedMute $true | Out-Null

            # Verify devices actually disabled
            Verify-DevicesFromState -Devices $disabledDevices -Expected "Disabled" | Out-Null

            # Verify adapters actually not-up
            Verify-AdaptersByName -Names $disabledAdapters -Expected "NotUp" | Out-Null
        }

        # 4) Freeze user-safe processes (never OS/session critical, never terminals)
        $suspended = Suspend-UserSafeProcesses

        # 5) Final state + report (must happen after freeze so suspended_pids is accurate)
        $events = Get-RecentEventBundles
        Save-State -DisabledDevices $disabledDevices -DisabledAdapters $disabledAdapters -SuspendedPids $suspended -AudioBefore $audioBefore
        New-Report -EventBundles $events
        Open-Report

        Write-Action -Step "done" -Action "exit" -Result "OK" -Details "Completed"
        Write-Host "Completed. Report: $ReportPath"
        exit 0
    }
    else {
        # Restore
        $st = Load-State
        if (-not $st) { throw "state.json not found or unreadable: $StatePath" }

        # 1) Resume suspended processes
        try {
            $pids = @()
            foreach ($x in @($st.suspended_pids)) { $pids += [int]$x }
            Resume-SuspendedPids -Pids $pids
        } catch {
            Write-Action -Step "freeze" -Action "resume" -Result "WARN" -Details $_.Exception.Message
        }

        # 2) Re-enable adapters we disabled
        try {
            $names = @()
            foreach ($n in @($st.disabled_adapters)) { $names += [string]$n }
            Enable-AdaptersByName -Names $names
        } catch {
            Write-Action -Step "network" -Action "enable" -Result "WARN" -Details $_.Exception.Message
        }

        # 3) Re-enable devices we disabled
        try {
            Enable-PnpByInstanceIds -DevicesFromState @($st.disabled_devices)
        } catch {
            Write-Action -Step "devices" -Action "enable" -Result "WARN" -Details $_.Exception.Message
        }

        # 4) Restore audio mute + volume (best-effort)
        try {
            if ($st.audio_before) {
                if ($null -ne $st.audio_before.mute) {
                    Set-AudioMute -Mute ([bool]$st.audio_before.mute)
                } else {
                    Set-AudioMute -Mute $false
                }

                if ($null -ne $st.audio_before.volume) {
                    Set-AudioVolumeScalar -Volume ([double]$st.audio_before.volume)
                }
            } else {
                # if we cannot read previous state, at least unmute
                Set-AudioMute -Mute $false
            }
        } catch {
            Write-Action -Step "audio" -Action "restore" -Result "WARN" -Details $_.Exception.Message
        }

        if ($Cfg.EnableVerification -and -not $DryRun) {
            # Verify adapters are Up again
            $names = @()
            foreach ($n in @($st.disabled_adapters)) { $names += [string]$n }
            Verify-AdaptersByName -Names $names -Expected "Up" | Out-Null

            # Verify devices are Enabled again
            Verify-DevicesFromState -Devices @($st.disabled_devices) -Expected "Enabled" | Out-Null

            # Verify audio matches snapshot (best-effort)
            if ($st.audio_before -and ($null -ne $st.audio_before.mute)) {
                Verify-AudioMute -ExpectedMute ([bool]$st.audio_before.mute) | Out-Null
            }
            if ($st.audio_before -and ($null -ne $st.audio_before.volume)) {
                Verify-AudioVolume -ExpectedVolume ([double]$st.audio_before.volume) | Out-Null
            }
        }

        $events = Get-RecentEventBundles
        New-Report -EventBundles $events
        Open-Report

        Write-Action -Step "done" -Action "exit" -Result "OK" -Details "Restore completed"
        Write-Host "Restore completed. Report: $ReportPath"
        exit 0
    }
}
catch {
    Write-Action -Step "fatal" -Action "exception" -Result "FAIL" -Details $_.Exception.Message
    Write-Host "FAILED: $($_.Exception.Message)"
    Write-Host "Actions log: $ActionsPath"
    exit 1
}
