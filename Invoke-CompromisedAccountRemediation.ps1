#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Interactive remediation runbook for a compromised Microsoft 365 account.

.DESCRIPTION
    Presents an action menu covering all five phases of account compromise remediation:

        Phase 1 – Immediate Containment
            [1]  Block sign-in
            [2]  Revoke all active sessions & refresh tokens

        Phase 2 – Credential & Identity Reset
            [3]  Force password reset
            [4]  Mark user as Compromised (Entra ID Protection / P2)

        Phase 3 – Investigate Blast Radius
            [5]  Export sign-in activity report (CSV)
            [6]  Inspect mailbox for compromise indicators
            [7]  Review OneDrive / SharePoint audit activity (CSV)

        Phase 4 – Clean-Up & Recovery
            [8]  Remove malicious inbox rules
            [9]  Remove suspicious OAuth app consents
            [10] Remove external mailbox forwarding
            [11] Remove unrecognised MFA / authentication methods
            [12] Re-enable user access

        Phase 5 – Hardening
            [13] Review Conditional Access policies
            [14] Check security monitoring configuration

        [A]  Run ALL steps (1–12) automatically, then show hardening review

    Required permissions:
        Microsoft Graph (delegated or app):
            User.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All,
            AuditLog.Read.All, IdentityRiskyUser.ReadWrite.All (P2),
            Policy.Read.All, DelegatedPermissionGrant.ReadWrite.All,
            Application.Read.All
        Exchange Online:
            View-Only Recipients, Mail Recipients, Mailbox Import Export,
            View-Only Audit Logs (for unified audit log)

    Install required modules (once, as admin):
        Install-Module ExchangeOnlineManagement -Scope CurrentUser
        Install-Module Microsoft.Graph          -Scope CurrentUser

.PARAMETER UserPrincipalName
    UPN of the compromised account (e.g. jdoe@contoso.com).
    Prompted interactively if omitted.

.PARAMETER ReportFolder
    Folder where CSV reports are saved. Defaults to the current directory.

.PARAMETER LogPath
    Path for the remediation action log. Defaults to .\Remediation_<UPN>_<timestamp>.log

.PARAMETER NonInteractive
    Switch. Skip per-step confirmation prompts (use with caution in automation).

.EXAMPLE
    .\Invoke-CompromisedAccountRemediation.ps1 -UserPrincipalName jdoe@contoso.com

.EXAMPLE
    .\Invoke-CompromisedAccountRemediation.ps1 -UserPrincipalName jdoe@contoso.com `
        -ReportFolder "C:\IR\contoso" -NonInteractive
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $UserPrincipalName = "",
    [string] $ReportFolder      = "",
    [string] $LogPath           = "",
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Completed-step tracker (used by "Run All" and re-enable gate) ─────────────
$script:CompletedSteps = [System.Collections.Generic.HashSet[int]]::new()

#region ── Helpers ──────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
}

function Write-Header {
    param([string]$Title)
    $border = "─" * 60
    Write-Host ""
    Write-Host $border                   -ForegroundColor DarkCyan
    Write-Host "  $Title"               -ForegroundColor Cyan
    Write-Host $border                   -ForegroundColor DarkCyan
}

function Write-StepInfo {
    param([string]$Message)
    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor White
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✔ $Message" -ForegroundColor Green
    Write-Log $Message "SUCCESS"
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  ⚠ $Message" -ForegroundColor Yellow
    Write-Log $Message "WARN"
}

function Write-Err {
    param([string]$Message)
    Write-Host "  ✘ $Message" -ForegroundColor Red
    Write-Log $Message "ERROR"
}

function Confirm-Action {
    param([string]$Prompt)
    if ($NonInteractive) { return $true }
    $ans = Read-Host "  $Prompt [Y/N]"
    return ($ans -match '^[Yy]')
}

function New-TempPassword {
    $upper   = [char[]](65..90)  | Get-Random -Count 3
    $lower   = [char[]](97..122) | Get-Random -Count 4
    $digits  = [char[]](48..57)  | Get-Random -Count 3
    $special = [char[]]'!@#$%^&*' | Get-Random -Count 2
    $all     = ($upper + $lower + $digits + $special) | Sort-Object { Get-Random }
    return -join $all
}

function Get-ReportPath {
    param([string]$FileName)
    return Join-Path $script:ReportFolder $FileName
}

#endregion

#region ── Connection ────────────────────────────────────────────────────────────

function Connect-AllServices {
    Write-Header "Connecting to Microsoft Services"

    # Microsoft Graph
    Write-StepInfo "Connecting to Microsoft Graph..."
    $scopes = @(
        "User.ReadWrite.All"
        "UserAuthenticationMethod.ReadWrite.All"
        "AuditLog.Read.All"
        "IdentityRiskyUser.ReadWrite.All"
        "Policy.Read.All"
        "DelegatedPermissionGrant.ReadWrite.All"
        "Application.Read.All"
        "Directory.Read.All"
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Success "Connected to Microsoft Graph."
    }
    catch {
        Write-Err "Graph connection failed: $_"
        exit 1
    }

    # Exchange Online
    Write-StepInfo "Connecting to Exchange Online..."
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Success "Connected to Exchange Online."
    }
    catch {
        Write-Err "Exchange Online connection failed: $_"
        exit 1
    }
}

function Disconnect-AllServices {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }              catch {}
}

#endregion

#region ── User resolution ───────────────────────────────────────────────────────

function Resolve-TargetUser {
    param([string]$UPN)

    Write-StepInfo "Resolving user: $UPN"
    try {
        $u = Get-MgUser -UserId $UPN `
            -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,Mail,JobTitle,Department" `
            -ErrorAction Stop
        return $u
    }
    catch {
        Write-Err "User not found: $UPN"
        return $null
    }
}

function Show-UserBanner {
    param($User)
    Write-Host ""
    Write-Host "  Target account" -ForegroundColor DarkYellow
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ("  Name       : {0}" -f $User.DisplayName)      -ForegroundColor Yellow
    Write-Host ("  UPN        : {0}" -f $User.UserPrincipalName) -ForegroundColor Yellow
    Write-Host ("  Object ID  : {0}" -f $User.Id)               -ForegroundColor Yellow
    Write-Host ("  Sign-in    : {0}" -f $(if ($User.AccountEnabled) { "ENABLED" } else { "BLOCKED" })) `
        -ForegroundColor $(if ($User.AccountEnabled) { "Red" } else { "Green" })
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

#endregion

#region ── Phase 1 – Immediate Containment ──────────────────────────────────────

function Invoke-BlockSignIn {
    param($User)
    Write-Header "Step 1 · Block Sign-In"

    if (-not $User.AccountEnabled) {
        Write-Warn "Account is already blocked. Skipping."
        $script:CompletedSteps.Add(1) | Out-Null
        return
    }

    if (-not (Confirm-Action "Block sign-in for $($User.UserPrincipalName)?")) { return }

    try {
        Update-MgUser -UserId $User.Id -AccountEnabled:$false -ErrorAction Stop
        Write-Success "Sign-in blocked for $($User.UserPrincipalName)."
        Write-Log "Blocked sign-in for $($User.UserPrincipalName) (ID: $($User.Id))"
        $script:CompletedSteps.Add(1) | Out-Null
    }
    catch {
        Write-Err "Failed to block sign-in: $_"
    }
}

function Invoke-RevokeSessions {
    param($User)
    Write-Header "Step 2 · Revoke All Sessions & Refresh Tokens"

    if (-not (Confirm-Action "Revoke all active sessions for $($User.UserPrincipalName)?")) { return }

    try {
        Revoke-MgUserSignInSession -UserId $User.Id -ErrorAction Stop | Out-Null
        Write-Success "All sign-in sessions and refresh tokens revoked."
        Write-Log "Revoked sessions for $($User.UserPrincipalName)"
        $script:CompletedSteps.Add(2) | Out-Null
    }
    catch {
        Write-Err "Failed to revoke sessions: $_"
    }

    # List and offer removal of registered MFA methods as an advisory
    Write-StepInfo "Tip: Also reset MFA methods (Step 11) to fully remove attacker persistence."
}

#endregion

#region ── Phase 2 – Credential & Identity Reset ────────────────────────────────

function Invoke-ForcePasswordReset {
    param($User)
    Write-Header "Step 3 · Force Password Reset"

    $tempPass = New-TempPassword

    Write-Host ""
    Write-Host "  A temporary password will be set and the user will be required" -ForegroundColor White
    Write-Host "  to change it on next sign-in." -ForegroundColor White
    Write-Host ""
    Write-Host ("  Temporary password: {0}" -f $tempPass) -ForegroundColor Magenta
    Write-Host "  ⚠  Record this password before continuing." -ForegroundColor Yellow
    Write-Host ""

    if (-not (Confirm-Action "Set temporary password and force change at next sign-in?")) { return }

    $profile = @{
        Password                      = $tempPass
        ForceChangePasswordNextSignIn = $true
    }

    try {
        Update-MgUser -UserId $User.Id -PasswordProfile $profile -ErrorAction Stop
        Write-Success "Password reset. User must change password at next sign-in."
        Write-Log "Password reset for $($User.UserPrincipalName). ForceChange=true."
        $script:CompletedSteps.Add(3) | Out-Null
    }
    catch {
        Write-Err "Password reset failed: $_"
        Write-Warn "Note: Resetting passwords for Global Admins requires the Privileged Authentication Administrator role."
    }
}

function Invoke-MarkCompromised {
    param($User)
    Write-Header "Step 4 · Mark User as Compromised (Entra ID Protection)"

    Write-Warn "Requires Entra ID P2 and IdentityRiskyUser.ReadWrite.All permission."

    if (-not (Confirm-Action "Confirm $($User.UserPrincipalName) as compromised in Entra ID Protection?")) { return }

    try {
        $body = @{ UserIds = @($User.Id) }
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised" `
            -Body ($body | ConvertTo-Json) `
            -ContentType "application/json" `
            -ErrorAction Stop
        Write-Success "User confirmed as compromised in Entra ID Protection."
        Write-Log "Marked $($User.UserPrincipalName) as compromised in ID Protection."
        $script:CompletedSteps.Add(4) | Out-Null
    }
    catch {
        Write-Err "Could not mark user as compromised: $_"
        Write-Warn "This step requires Entra ID P2. You can also do this manually:"
        Write-Host "  Entra admin center → Protection → Risky users → Confirm compromised" -ForegroundColor DarkGray
    }
}

#endregion

#region ── Phase 3 – Investigate Blast Radius ───────────────────────────────────

function Invoke-ExportSignInActivity {
    param($User)
    Write-Header "Step 5 · Export Sign-In Activity Report"

    $days = 30
    if (-not $NonInteractive) {
        $input = Read-Host "  How many days of sign-in history to export? [default: 30]"
        if ($input -match '^\d+$') { $days = [int]$input }
    }

    $since   = (Get-Date).AddDays(-$days).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filter  = "userId eq '$($User.Id)' and createdDateTime ge $since"
    $csvPath = Get-ReportPath ("SignInActivity_{0}_{1}.csv" -f ($User.UserPrincipalName -replace '@','_at_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))

    Write-StepInfo "Fetching sign-in logs for the last $days days..."

    try {
        $logs = Get-MgAuditLogSignIn -Filter $filter -All -PageSize 999 -ErrorAction Stop

        if ($logs.Count -eq 0) {
            Write-Warn "No sign-in records found for the specified period."
            return
        }

        $logs | Select-Object `
            CreatedDateTime, UserDisplayName, UserPrincipalName,
            AppDisplayName, ClientAppUsed, IpAddress,
            @{N="City";        E={ $_.Location.City }},
            @{N="Country";     E={ $_.Location.CountryOrRegion }},
            @{N="Latitude";    E={ $_.Location.GeoCoordinates.Latitude }},
            @{N="Longitude";   E={ $_.Location.GeoCoordinates.Longitude }},
            @{N="RiskLevel";   E={ $_.RiskLevelDuringSignIn }},
            @{N="RiskState";   E={ $_.RiskState }},
            @{N="Status";      E={ $_.Status.ErrorCode }},
            @{N="MfaResult";   E={ $_.MfaDetail.AuthMethod }},
            ConditionalAccessStatus, IsInteractive,
            CorrelationId, Id |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

        Write-Success "Exported $($logs.Count) sign-in records to: $csvPath"
        Write-Log "Exported $($logs.Count) sign-in records to $csvPath"

        # Quick anomaly summary
        $uniqueCountries = $logs | ForEach-Object { $_.Location.CountryOrRegion } | Sort-Object -Unique
        $legacyAuth      = $logs | Where-Object { $_.ClientAppUsed -match "SMTP|POP|IMAP|MAPI|EAS|legacy" }
        $failedLogins    = $logs | Where-Object { $_.Status.ErrorCode -ne 0 }

        Write-Host ""
        Write-Host "  ── Quick Anomaly Summary ──────────────────────────" -ForegroundColor DarkYellow
        Write-Host ("  Unique countries  : {0}" -f ($uniqueCountries -join ", ")) -ForegroundColor White
        Write-Host ("  Legacy auth events: {0}" -f $legacyAuth.Count)             -ForegroundColor $(if ($legacyAuth.Count -gt 0) {"Red"} else {"White"})
        Write-Host ("  Failed sign-ins   : {0}" -f $failedLogins.Count)           -ForegroundColor $(if ($failedLogins.Count -gt 0) {"Yellow"} else {"White"})
        Write-Host "  Review the CSV for impossible travel and unknown IPs." -ForegroundColor DarkGray

        $script:CompletedSteps.Add(5) | Out-Null
    }
    catch {
        Write-Err "Failed to retrieve sign-in logs: $_"
        Write-Warn "Ensure AuditLog.Read.All permission is granted."
    }
}

function Invoke-CheckMailboxIndicators {
    param($User)
    Write-Header "Step 6 · Inspect Mailbox for Compromise Indicators"

    $upn     = $User.UserPrincipalName
    $csvPath = Get-ReportPath ("MailboxIndicators_{0}_{1}.csv" -f ($upn -replace '@','_at_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Inbox rules ─────────────────────────────────────────────────────────
    Write-StepInfo "Checking inbox rules..."
    try {
        $rules = Get-InboxRule -Mailbox $upn -ErrorAction Stop
        foreach ($rule in $rules) {
            $suspicious = $false
            $reasons    = @()

            if ($rule.ForwardTo)                          { $suspicious = $true; $reasons += "ForwardTo set" }
            if ($rule.ForwardAsAttachmentTo)              { $suspicious = $true; $reasons += "ForwardAsAttachmentTo set" }
            if ($rule.RedirectTo)                         { $suspicious = $true; $reasons += "RedirectTo set" }
            if ($rule.DeleteMessage)                      { $suspicious = $true; $reasons += "Deletes matching messages" }
            if ($rule.MoveToFolder -match "RSS|Junk")     { $suspicious = $true; $reasons += "Moves to Junk/RSS" }
            if ($null -ne $rule.MarkAsRead -and
                $rule.MarkAsRead -and
                ($rule.DeleteMessage -or $rule.ForwardTo)){ $suspicious = $true; $reasons += "Marks as read + acts on message" }

            $findings.Add([PSCustomObject]@{
                Category  = "Inbox Rule"
                Name      = $rule.Name
                Enabled   = $rule.Enabled
                Suspicious = $suspicious
                Details   = ($reasons -join "; ")
                RawValue  = $rule.RuleIdentity
            })
        }

        $suspCount = ($findings | Where-Object Suspicious).Count
        if ($suspCount -gt 0) {
            Write-Warn "$suspCount suspicious inbox rule(s) found. Review and use Step 8 to remove."
        } else {
            Write-Success "No obviously suspicious inbox rules detected ($($rules.Count) rules checked)."
        }
    }
    catch {
        Write-Err "Could not retrieve inbox rules: $_"
    }

    # --- Mailbox forwarding ──────────────────────────────────────────────────
    Write-StepInfo "Checking mailbox forwarding settings..."
    try {
        $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop
        $fwdSet = $false

        if ($mbx.ForwardingAddress) {
            Write-Warn "ForwardingAddress: $($mbx.ForwardingAddress)"
            $findings.Add([PSCustomObject]@{
                Category   = "Mailbox Forwarding"
                Name       = "ForwardingAddress"
                Enabled    = $true
                Suspicious = $true
                Details    = $mbx.ForwardingAddress
                RawValue   = $mbx.ForwardingAddress
            })
            $fwdSet = $true
        }
        if ($mbx.ForwardingSmtpAddress) {
            Write-Warn "ForwardingSmtpAddress: $($mbx.ForwardingSmtpAddress)"
            $findings.Add([PSCustomObject]@{
                Category   = "Mailbox Forwarding"
                Name       = "ForwardingSmtpAddress"
                Enabled    = $true
                Suspicious = $true
                Details    = $mbx.ForwardingSmtpAddress
                RawValue   = $mbx.ForwardingSmtpAddress
            })
            $fwdSet = $true
        }
        if (-not $fwdSet) {
            Write-Success "No mailbox-level forwarding configured."
        }
    }
    catch {
        Write-Err "Could not check mailbox forwarding: $_"
    }

    # --- Sent items check (advisory) ─────────────────────────────────────────
    Write-StepInfo "Checking for sent-items evidence of phishing..."
    try {
        $sent = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
            -UserIds $upn -RecordType ExchangeItem -Operations Send -ResultSize 50 -ErrorAction Stop

        if ($sent -and $sent.Count -gt 0) {
            Write-Warn "$($sent.Count) send events in the last 30 days found in audit log (first 50)."
            Write-Host "  Review these in the Defender portal for bulk/phishing sends." -ForegroundColor DarkGray
            $findings.Add([PSCustomObject]@{
                Category   = "Sent Items"
                Name       = "Recent Send Events"
                Enabled    = $true
                Suspicious = $false
                Details    = "$($sent.Count) send events in 30 days (audit, first 50 shown)"
                RawValue   = ""
            })
        }
    }
    catch {
        Write-Warn "Could not query unified audit log for send events (requires View-Only Audit Logs role)."
    }

    # --- Export ──────────────────────────────────────────────────────────────
    if ($findings.Count -gt 0) {
        $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Success "Mailbox indicators exported to: $csvPath"
        Write-Log "Mailbox indicator report saved to $csvPath ($($findings.Count) items)"
    }

    $script:CompletedSteps.Add(6) | Out-Null
}

function Invoke-ReviewCloudStorageActivity {
    param($User)
    Write-Header "Step 7 · Review OneDrive / SharePoint Audit Activity"

    $csvPath = Get-ReportPath ("CloudStorageActivity_{0}_{1}.csv" -f ($User.UserPrincipalName -replace '@','_at_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))

    Write-Warn "Requires View-Only Audit Logs role. Data may take up to 24h to appear."

    $operations = @(
        "FileDownloaded","FilePreviewed","FileAccessed",
        "SharingInvitationCreated","AnonymousLinkCreated","AddedToSecureLink",
        "FileDeleted","FileRecycled","FolderDeleted",
        "FileUploaded","FileSyncDownloadedFull"
    )

    try {
        $days    = 30
        $results = Search-UnifiedAuditLog `
            -StartDate  (Get-Date).AddDays(-$days) `
            -EndDate    (Get-Date) `
            -UserIds    $User.UserPrincipalName `
            -RecordType SharePointFileOperation `
            -Operations $operations `
            -ResultSize 1000 `
            -ErrorAction Stop

        if (-not $results -or $results.Count -eq 0) {
            Write-Warn "No SharePoint/OneDrive activity found in the last $days days."
            $script:CompletedSteps.Add(7) | Out-Null
            return
        }

        $parsed = foreach ($entry in $results) {
            $data = $entry.AuditData | ConvertFrom-Json
            [PSCustomObject]@{
                Timestamp     = $entry.CreationDate
                Operation     = $entry.Operations
                Workload      = $data.Workload
                FileName      = $data.SourceFileName
                FilePath      = $data.SourceRelativeUrl
                SiteUrl       = $data.SiteUrl
                ClientIP      = $data.ClientIP
                UserAgent     = $data.UserAgent
                SharingTarget = $data.TargetUserOrGroupName
                Anonymous     = if ($data.PSObject.Properties["AnonymousLink"]) { $data.AnonymousLink } else { "" }
            }
        }

        $parsed | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

        $downloads = ($parsed | Where-Object Operation -eq "FileDownloaded").Count
        $shares    = ($parsed | Where-Object Operation -match "Sharing|Link").Count
        $deletes   = ($parsed | Where-Object Operation -match "Deleted|Recycled").Count

        Write-Success "Exported $($parsed.Count) events to: $csvPath"
        Write-Host ""
        Write-Host "  ── Cloud Storage Summary ──────────────────────────" -ForegroundColor DarkYellow
        Write-Host ("  File downloads       : {0}" -f $downloads) -ForegroundColor $(if ($downloads -gt 50) {"Red"} else {"White"})
        Write-Host ("  Sharing/link events  : {0}" -f $shares)    -ForegroundColor $(if ($shares    -gt 0)  {"Yellow"} else {"White"})
        Write-Host ("  Delete/recycle events: {0}" -f $deletes)   -ForegroundColor $(if ($deletes   -gt 0)  {"Yellow"} else {"White"})

        Write-Log "Cloud storage activity exported to $csvPath ($($parsed.Count) events)"
        $script:CompletedSteps.Add(7) | Out-Null
    }
    catch {
        Write-Err "Failed to query unified audit log: $_"
        Write-Warn "Ensure the account running this script has the 'View-Only Audit Logs' role in compliance center."
    }
}

#endregion

#region ── Phase 4 – Clean-Up & Recovery ────────────────────────────────────────

function Invoke-RemoveInboxRules {
    param($User)
    Write-Header "Step 8 · Remove Malicious Inbox Rules"

    try {
        $rules = @(Get-InboxRule -Mailbox $User.UserPrincipalName -ErrorAction Stop)

        if ($rules.Count -eq 0) {
            Write-Success "No inbox rules found."
            $script:CompletedSteps.Add(8) | Out-Null
            return
        }

        Write-Host ""
        Write-Host "  Current inbox rules:" -ForegroundColor White
        $i = 1
        foreach ($rule in $rules) {
            $flags = @()
            if ($rule.ForwardTo)           { $flags += "FWD:$($rule.ForwardTo)" }
            if ($rule.ForwardAsAttachmentTo){ $flags += "FWD-ATTACH" }
            if ($rule.RedirectTo)          { $flags += "REDIRECT:$($rule.RedirectTo)" }
            if ($rule.DeleteMessage)       { $flags += "DELETE" }
            $label = if ($flags) { "[SUSPICIOUS] " + ($flags -join " | ") } else { "[Normal]" }
            $color = if ($flags) { "Red" } else { "Gray" }
            Write-Host ("  [{0}] {1} — {2}" -f $i, $rule.Name, $label) -ForegroundColor $color
            $i++
        }

        Write-Host ""
        if ($NonInteractive) {
            $toRemove = $rules | Where-Object {
                $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage
            }
        } else {
            $ans = Read-Host "  Enter rule numbers to delete (e.g. 1,3), 'S' for suspicious only, or 'A' for all"
            $toRemove = switch -Regex ($ans.Trim()) {
                '^[Aa]$' { $rules }
                '^[Ss]$' { $rules | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage } }
                default  {
                    $indices = $ans -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 }
                    $indices | ForEach-Object { if ($_ -ge 0 -and $_ -lt $rules.Count) { $rules[$_] } }
                }
            }
        }

        if (-not $toRemove) { Write-Warn "No rules selected for removal."; return }

        foreach ($rule in $toRemove) {
            try {
                Remove-InboxRule -Identity $rule.RuleIdentity -Mailbox $User.UserPrincipalName -Force -ErrorAction Stop
                Write-Success "Removed rule: $($rule.Name)"
                Write-Log "Removed inbox rule '$($rule.Name)' from $($User.UserPrincipalName)"
            }
            catch {
                Write-Err "Failed to remove rule '$($rule.Name)': $_"
            }
        }

        $script:CompletedSteps.Add(8) | Out-Null
    }
    catch {
        Write-Err "Could not retrieve inbox rules: $_"
    }
}

function Invoke-RemoveOAuthConsents {
    param($User)
    Write-Header "Step 9 · Remove Suspicious OAuth App Consents"

    try {
        $grants = @(Get-MgUserOauth2PermissionGrant -UserId $User.Id -All -ErrorAction Stop)

        if ($grants.Count -eq 0) {
            Write-Success "No OAuth permission grants found for this user."
            $script:CompletedSteps.Add(9) | Out-Null
            return
        }

        Write-Host ""
        Write-Host "  OAuth app consents:" -ForegroundColor White

        # Enrich with app display names
        $enriched = foreach ($grant in $grants) {
            $appName = ""
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
                $appName = $sp.DisplayName
            } catch {}
            [PSCustomObject]@{
                Index       = 0
                AppName     = $appName
                ClientId    = $grant.ClientId
                Scope       = $grant.Scope
                ConsentType = $grant.ConsentType
                GrantId     = $grant.Id
            }
        }

        $i = 1
        foreach ($g in $enriched) {
            $g.Index = $i
            Write-Host ("  [{0}] {1} ({2})" -f $i, $g.AppName, $g.ClientId) -ForegroundColor White
            Write-Host ("      Scopes: {0}" -f $g.Scope)                     -ForegroundColor DarkGray
            $i++
        }

        Write-Host ""
        if ($NonInteractive) {
            Write-Warn "NonInteractive mode: skipping OAuth removal — review manually."
            return
        }

        $ans = Read-Host "  Enter numbers to revoke (e.g. 1,2), 'A' for all, or ENTER to skip"
        if ([string]::IsNullOrWhiteSpace($ans)) { return }

        $toRevoke = if ($ans -match '^[Aa]$') {
            $enriched
        } else {
            $indices = $ans -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 }
            $indices | ForEach-Object { if ($_ -ge 0 -and $_ -lt $enriched.Count) { $enriched[$_] } }
        }

        foreach ($g in $toRevoke) {
            try {
                Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $g.GrantId -ErrorAction Stop
                Write-Success "Revoked consent for: $($g.AppName)"
                Write-Log "Revoked OAuth consent for app '$($g.AppName)' (ClientId: $($g.ClientId)) from $($User.UserPrincipalName)"
            }
            catch {
                Write-Err "Failed to revoke '$($g.AppName)': $_"
            }
        }

        $script:CompletedSteps.Add(9) | Out-Null
    }
    catch {
        Write-Err "Could not retrieve OAuth grants: $_"
    }
}

function Invoke-RemoveMailboxForwarding {
    param($User)
    Write-Header "Step 10 · Remove External Mailbox Forwarding"

    try {
        $mbx = Get-Mailbox -Identity $User.UserPrincipalName -ErrorAction Stop
        $changed = $false

        if ($mbx.ForwardingAddress -or $mbx.ForwardingSmtpAddress) {
            Write-Host ""
            if ($mbx.ForwardingAddress)     { Write-Warn "ForwardingAddress     : $($mbx.ForwardingAddress)" }
            if ($mbx.ForwardingSmtpAddress) { Write-Warn "ForwardingSmtpAddress : $($mbx.ForwardingSmtpAddress)" }
            Write-Host ""

            if (Confirm-Action "Remove all mailbox-level forwarding for $($User.UserPrincipalName)?") {
                Set-Mailbox -Identity $User.UserPrincipalName `
                    -ForwardingAddress $null `
                    -ForwardingSmtpAddress $null `
                    -DeliverToMailboxAndForward $false `
                    -ErrorAction Stop
                Write-Success "Mailbox forwarding removed."
                Write-Log "Removed mailbox forwarding from $($User.UserPrincipalName)"
                $changed = $true
            }
        } else {
            Write-Success "No mailbox-level forwarding configured."
        }

        # Transport rules check (advisory)
        Write-StepInfo "Checking organisation transport rules for user-specific forwarding..."
        $transportRules = @(Get-TransportRule -ErrorAction SilentlyContinue |
            Where-Object { $_.From -contains $User.UserPrincipalName -or $_.SentTo -contains $User.UserPrincipalName })

        if ($transportRules.Count -gt 0) {
            Write-Warn "$($transportRules.Count) transport rule(s) reference this user. Review manually in EAC."
            foreach ($r in $transportRules) {
                Write-Host ("  - {0}" -f $r.Name) -ForegroundColor DarkGray
            }
        }

        $script:CompletedSteps.Add(10) | Out-Null
    }
    catch {
        Write-Err "Could not access mailbox settings: $_"
    }
}

function Invoke-RemoveMfaMethods {
    param($User)
    Write-Header "Step 11 · Remove Unrecognised MFA / Authentication Methods"

    try {
        $methods = @(Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop)

        if ($methods.Count -eq 0) {
            Write-Warn "No authentication methods registered."
            $script:CompletedSteps.Add(11) | Out-Null
            return
        }

        Write-Host ""
        Write-Host "  Registered authentication methods:" -ForegroundColor White

        $display = foreach ($m in $methods) {
            $type = ($m.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.","") ?? $m.GetType().Name
            $detail = switch -Wildcard ($type) {
                "*phone*"               { $m.AdditionalProperties["phoneNumber"] ?? "" }
                "*microsoftAuthenticator*" { $m.AdditionalProperties["displayName"] ?? "" }
                "*password*"            { "(password)" }
                "*fido2*"               { $m.AdditionalProperties["displayName"] ?? "" }
                "*softwareOath*"        { $m.AdditionalProperties["secretKey"] ?? "(TOTP)" }
                "*email*"               { $m.AdditionalProperties["emailAddress"] ?? "" }
                default                 { "" }
            }
            [PSCustomObject]@{
                Index  = 0
                Type   = $type
                Detail = $detail
                Id     = $m.Id
            }
        }

        $i = 1
        foreach ($d in $display) {
            $d.Index = $i
            Write-Host ("  [{0}] {1}  {2}" -f $i, $d.Type, $d.Detail) -ForegroundColor White
            $i++
        }

        Write-Host ""
        Write-Host "  NOTE: The password method cannot be deleted here." -ForegroundColor DarkGray
        Write-Host "        WindowsHello methods cannot be deleted via API." -ForegroundColor DarkGray
        Write-Host ""

        if ($NonInteractive) {
            Write-Warn "NonInteractive: review MFA methods manually. Skipping removal."
            return
        }

        $ans = Read-Host "  Enter numbers to remove (e.g. 1,3), 'A' for all non-password, or ENTER to skip"
        if ([string]::IsNullOrWhiteSpace($ans)) { return }

        $toRemove = if ($ans -match '^[Aa]$') {
            $display | Where-Object { $_.Type -notmatch "password|windowsHelloForBusiness" }
        } else {
            $indices = $ans -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 }
            $indices | ForEach-Object {
                if ($_ -ge 0 -and $_ -lt $display.Count) { $display[$_] }
            } | Where-Object { $_.Type -notmatch "password|windowsHelloForBusiness" }
        }

        foreach ($m in $toRemove) {
            try {
                $uri = "https://graph.microsoft.com/v1.0/users/$($User.Id)/authentication/$($m.Type)s/$($m.Id)"
                Invoke-MgGraphRequest -Method DELETE -Uri $uri -ErrorAction Stop
                Write-Success "Removed: $($m.Type) — $($m.Detail)"
                Write-Log "Removed auth method '$($m.Type)' ($($m.Id)) from $($User.UserPrincipalName)"
            }
            catch {
                Write-Err "Could not remove $($m.Type): $_"
                Write-Host "  Try removing it manually in Entra → Users → Authentication methods." -ForegroundColor DarkGray
            }
        }

        $script:CompletedSteps.Add(11) | Out-Null
    }
    catch {
        Write-Err "Could not retrieve authentication methods: $_"
    }
}

function Invoke-ReenableUser {
    param($User)
    Write-Header "Step 12 · Re-Enable User Access"

    # Gate: warn if critical containment/reset steps were skipped
    $requiredSteps   = @(1, 2, 3)
    $recommendedSteps = @(8, 10, 11)
    $missedRequired  = $requiredSteps  | Where-Object { $_ -notin $script:CompletedSteps }
    $missedRecommended = $recommendedSteps | Where-Object { $_ -notin $script:CompletedSteps }

    if ($missedRequired) {
        Write-Warn "The following critical steps have NOT been completed in this session:"
        $missedRequired | ForEach-Object { Write-Host ("  - Step {0}" -f $_) -ForegroundColor Red }
        if (-not (Confirm-Action "Re-enable user ANYWAY (not recommended)?")) { return }
    }

    if ($missedRecommended) {
        Write-Warn "Recommended clean-up steps not yet completed: Steps $($missedRecommended -join ', ')"
        if (-not (Confirm-Action "Continue re-enabling without completing those steps?")) { return }
    }

    $u = Get-MgUser -UserId $User.Id -Property "AccountEnabled" -ErrorAction SilentlyContinue
    if ($u -and $u.AccountEnabled) {
        Write-Warn "Account is already enabled."
        $script:CompletedSteps.Add(12) | Out-Null
        return
    }

    if (-not (Confirm-Action "Re-enable sign-in for $($User.UserPrincipalName)?")) { return }

    try {
        Update-MgUser -UserId $User.Id -AccountEnabled:$true -ErrorAction Stop
        Write-Success "Account re-enabled. User will need to MFA re-enroll on next sign-in."
        Write-Warn "Ensure MFA is fully re-enrolled before communicating the temp password to the user."
        Write-Log "Re-enabled account for $($User.UserPrincipalName)"
        $script:CompletedSteps.Add(12) | Out-Null
    }
    catch {
        Write-Err "Failed to re-enable account: $_"
    }
}

#endregion

#region ── Phase 5 – Hardening ──────────────────────────────────────────────────

function Invoke-ReviewConditionalAccess {
    Write-Header "Step 13 · Review Conditional Access Policies"

    try {
        $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)

        if ($policies.Count -eq 0) {
            Write-Warn "No Conditional Access policies found. This tenant may have no CA configured."
            return
        }

        $mfaPolicy     = $policies | Where-Object {
            $_.GrantControls.BuiltInControls -contains "mfa" -and
            $_.State -eq "enabled"
        }
        $blockLegacy   = $policies | Where-Object {
            $_.Conditions.ClientAppTypes -match "exchangeActiveSync|other" -and
            $_.GrantControls.Operator -eq "OR" -and
            $_.GrantControls.BuiltInControls -contains "block" -and
            $_.State -eq "enabled"
        }

        Write-Host ""
        Write-Host "  ── Conditional Access Overview ────────────────────" -ForegroundColor DarkYellow
        Write-Host ("  Total policies     : {0}" -f $policies.Count)

        Write-Host ("  Enabled MFA policies: {0}" -f $mfaPolicy.Count) `
            -ForegroundColor $(if ($mfaPolicy.Count -gt 0) {"Green"} else {"Red"})

        Write-Host ("  Legacy auth block  : {0}" -f $(if ($blockLegacy.Count -gt 0) {"Present"} else {"NOT FOUND"})) `
            -ForegroundColor $(if ($blockLegacy.Count -gt 0) {"Green"} else {"Red"})

        Write-Host ""
        Write-Host "  All policies:" -ForegroundColor White
        foreach ($p in ($policies | Sort-Object DisplayName)) {
            $stateColor = switch ($p.State) {
                "enabled"      { "Green" }
                "enabledForReportingButNotEnforced" { "Yellow" }
                default        { "Gray" }
            }
            Write-Host ("  [{0,-30}] {1}" -f $p.DisplayName, $p.State) -ForegroundColor $stateColor
        }

        if ($mfaPolicy.Count -eq 0) {
            Write-Host ""
            Write-Warn "No enforced MFA policy detected. Strongly recommend enabling MFA for all users."
        }
        if ($blockLegacy.Count -eq 0) {
            Write-Warn "No legacy authentication block detected. Legacy auth bypasses MFA."
        }

        Write-Log "CA policy review: $($policies.Count) policies, MFA:$($mfaPolicy.Count), LegacyBlock:$($blockLegacy.Count)"
        $script:CompletedSteps.Add(13) | Out-Null
    }
    catch {
        Write-Err "Could not retrieve Conditional Access policies: $_"
        Write-Host "  Requires Policy.Read.All permission." -ForegroundColor DarkGray
    }
}

function Invoke-CheckSecurityMonitoring {
    Write-Header "Step 14 · Check Security Monitoring Configuration"

    Write-Host ""
    Write-Host "  Checking available security configurations..." -ForegroundColor White

    # Audit log status
    try {
        $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
        $auditEnabled = $auditConfig.UnifiedAuditLogIngestionEnabled
        Write-Host ("  Unified Audit Log  : {0}" -f $(if ($auditEnabled) {"ENABLED"} else {"DISABLED"})) `
            -ForegroundColor $(if ($auditEnabled) {"Green"} else {"Red"})
        if (-not $auditEnabled) {
            Write-Warn "Unified Audit Log is disabled. Run: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true"
        }
    }
    catch {
        Write-Warn "Could not check audit log config: $_"
    }

    # Mailbox audit
    try {
        $mbxAudit = Get-OrganizationConfig -ErrorAction Stop | Select-Object -ExpandProperty AuditDisabled
        Write-Host ("  Mailbox Auditing   : {0}" -f $(if (-not $mbxAudit) {"ENABLED (org default)"} else {"DISABLED"})) `
            -ForegroundColor $(if (-not $mbxAudit) {"Green"} else {"Red"})
    }
    catch {
        Write-Warn "Could not check mailbox audit config."
    }

    # Entra ID Protection (advisory via Graph)
    try {
        $riskyUsers = @(Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=1" `
            -ErrorAction Stop)
        Write-Host "  Entra ID Protection: AVAILABLE (P2 detected)" -ForegroundColor Green
    }
    catch {
        Write-Host "  Entra ID Protection: NOT AVAILABLE or insufficient permissions (P2 required)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ── Recommendations ────────────────────────────────" -ForegroundColor DarkYellow
    Write-Host "  ✔ Enable Defender for Office 365 Plan 1 or 2 alerts" -ForegroundColor White
    Write-Host "  ✔ Configure risky user alerts in Entra ID Protection" -ForegroundColor White
    Write-Host "  ✔ Set audit log retention to 180+ days (E3) or 1 year (E5)" -ForegroundColor White
    Write-Host "  ✔ Review alert policies in the Microsoft Defender portal" -ForegroundColor White
    Write-Host "  ✔ Enable Microsoft Secure Score recommendations" -ForegroundColor White

    Write-Log "Security monitoring review completed."
    $script:CompletedSteps.Add(14) | Out-Null
}

#endregion

#region ── Run All ───────────────────────────────────────────────────────────────

function Invoke-RunAll {
    param($User)

    Write-Host ""
    Write-Host "  This will run Steps 1–12 in sequence." -ForegroundColor Yellow
    Write-Host "  You will be prompted before each destructive action." -ForegroundColor Yellow
    Write-Host ""
    if (-not (Confirm-Action "Proceed with full remediation for $($User.UserPrincipalName)?")) { return }

    Invoke-BlockSignIn        $User
    Invoke-RevokeSessions     $User
    Invoke-ForcePasswordReset $User
    Invoke-MarkCompromised    $User
    Invoke-ExportSignInActivity $User
    Invoke-CheckMailboxIndicators $User
    Invoke-ReviewCloudStorageActivity $User
    Invoke-RemoveInboxRules   $User
    Invoke-RemoveOAuthConsents $User
    Invoke-RemoveMailboxForwarding $User
    Invoke-RemoveMfaMethods   $User
    Invoke-ReenableUser       $User

    Write-Header "All Steps Complete — Hardening Review"
    Invoke-ReviewConditionalAccess
    Invoke-CheckSecurityMonitoring
}

#endregion

#region ── Menu ──────────────────────────────────────────────────────────────────

function Show-Menu {
    param($User)

    $done  = $script:CompletedSteps
    $tick  = { param($n) if ($n -in $done) { "✔" } else { " " } }

    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        MS365 Compromised Account Remediation Runbook         ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Show-UserBanner $User

    Write-Host "  [A] RUN ALL STEPS (1–12) automatically" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  ── Phase 1: Immediate Containment ─────────────────────────" -ForegroundColor DarkYellow
    Write-Host ("  [{0}] [1] Block sign-in"                               -f (& $tick 1))
    Write-Host ("  [{0}] [2] Revoke all sessions & refresh tokens"        -f (& $tick 2))
    Write-Host ""
    Write-Host "  ── Phase 2: Credential & Identity Reset ───────────────────" -ForegroundColor DarkYellow
    Write-Host ("  [{0}] [3] Force password reset"                        -f (& $tick 3))
    Write-Host ("  [{0}] [4] Mark user as Compromised (Entra ID P2)"      -f (& $tick 4))
    Write-Host ""
    Write-Host "  ── Phase 3: Investigate Blast Radius ──────────────────────" -ForegroundColor DarkYellow
    Write-Host ("  [{0}] [5] Export sign-in activity report"              -f (& $tick 5))
    Write-Host ("  [{0}] [6] Inspect mailbox for compromise indicators"   -f (& $tick 6))
    Write-Host ("  [{0}] [7] Review OneDrive/SharePoint audit activity"   -f (& $tick 7))
    Write-Host ""
    Write-Host "  ── Phase 4: Clean-Up & Recovery ───────────────────────────" -ForegroundColor DarkYellow
    Write-Host ("  [{0}] [8] Remove malicious inbox rules"                -f (& $tick 8))
    Write-Host ("  [{0}] [9] Remove suspicious OAuth app consents"        -f (& $tick 9))
    Write-Host ("  [{0}][10] Remove external mailbox forwarding"          -f (& $tick 10))
    Write-Host ("  [{0}][11] Remove unrecognised MFA methods"             -f (& $tick 11))
    Write-Host ("  [{0}][12] Re-enable user access"                       -f (& $tick 12))
    Write-Host ""
    Write-Host "  ── Phase 5: Hardening ─────────────────────────────────────" -ForegroundColor DarkYellow
    Write-Host ("  [{0}][13] Review Conditional Access policies"          -f (& $tick 13))
    Write-Host ("  [{0}][14] Check security monitoring configuration"     -f (& $tick 14))
    Write-Host ""
    Write-Host "  [Q] Quit" -ForegroundColor DarkGray
    Write-Host ""
}

#endregion

#region ── Main ──────────────────────────────────────────────────────────────────

# Paths
if (-not $ReportFolder) { $ReportFolder = (Get-Location).Path }
if (-not (Test-Path $ReportFolder)) { New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null }

$ts = Get-Date -Format "yyyyMMdd_HHmmss"

# Connect
Connect-AllServices

# Resolve user
if (-not $UserPrincipalName) {
    $UserPrincipalName = Read-Host "`n  Enter the UPN of the compromised account"
}

$targetUser = Resolve-TargetUser -UPN $UserPrincipalName
if (-not $targetUser) {
    Write-Error "Could not find user '$UserPrincipalName'. Exiting."
    Disconnect-AllServices
    exit 1
}

# Set log path after UPN is known
if (-not $LogPath) {
    $safeName = $UserPrincipalName -replace '[^\w]','_'
    $LogPath  = Join-Path $ReportFolder "Remediation_${safeName}_${ts}.log"
}
$script:LogPath = $LogPath

Write-Log "=== Remediation session started for $UserPrincipalName ==="

# Menu loop
do {
    Show-Menu -User $targetUser
    $choice = Read-Host "  Select an option"

    # Refresh user object each iteration to reflect current state
    $targetUser = Resolve-TargetUser -UPN $UserPrincipalName

    switch ($choice.Trim().ToUpper()) {
        "A"  { Invoke-RunAll                       $targetUser }
        "1"  { Invoke-BlockSignIn                  $targetUser }
        "2"  { Invoke-RevokeSessions               $targetUser }
        "3"  { Invoke-ForcePasswordReset           $targetUser }
        "4"  { Invoke-MarkCompromised              $targetUser }
        "5"  { Invoke-ExportSignInActivity         $targetUser }
        "6"  { Invoke-CheckMailboxIndicators       $targetUser }
        "7"  { Invoke-ReviewCloudStorageActivity   $targetUser }
        "8"  { Invoke-RemoveInboxRules             $targetUser }
        "9"  { Invoke-RemoveOAuthConsents          $targetUser }
        "10" { Invoke-RemoveMailboxForwarding      $targetUser }
        "11" { Invoke-RemoveMfaMethods             $targetUser }
        "12" { Invoke-ReenableUser                 $targetUser }
        "13" { Invoke-ReviewConditionalAccess }
        "14" { Invoke-CheckSecurityMonitoring }
        "Q"  { break }
        default { Write-Warn "Invalid option. Please try again." }
    }

    if ($choice.Trim().ToUpper() -ne "Q") {
        Write-Host ""
        Read-Host "  Press ENTER to return to the menu"
    }

} while ($choice.Trim().ToUpper() -ne "Q")

Write-Log "=== Remediation session ended. Steps completed: $($script:CompletedSteps -join ', ') ==="
Write-Host ""
Write-Host "  Completed steps : $($script:CompletedSteps | Sort-Object | Join-String -Separator ', ')" -ForegroundColor Cyan
Write-Host "  Action log      : $($script:LogPath)" -ForegroundColor Cyan
Write-Host "  Reports folder  : $ReportFolder" -ForegroundColor Cyan
Write-Host ""

Disconnect-AllServices

#endregion
