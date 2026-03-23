#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Search for phishing messages and delete them from all affected mailboxes.

.DESCRIPTION
    Uses Content Search (via Security & Compliance PowerShell) to locate phishing
    emails by subject, sender, header, or body keywords, then performs a soft- or
    hard-delete across every matched mailbox.

    Required roles (assign before running):
        - Compliance Administrator  OR  eDiscovery Manager
        - Search And Purge (in the Security & Compliance Center)

.PARAMETER Subject
    Exact or partial subject line to search for (supports KQL wildcards).

.PARAMETER SenderAddress
    Sender email address to match (e.g. attacker@evil.com).

.PARAMETER RecipientAddress
    Filter results to a specific recipient. Omit to target all mailboxes.

.PARAMETER BodyKeywords
    One or more keywords that must appear in the message body (joined with AND).

.PARAMETER AttachmentName
    Filename or partial name of a suspicious attachment.

.PARAMETER MessageId
    Internet Message-ID header value (angle brackets optional).

.PARAMETER StartDate
    Earliest sent date to include in the search (YYYY-MM-DD).

.PARAMETER EndDate
    Latest sent date to include in the search (YYYY-MM-DD).

.PARAMETER PurgeType
    SoftDelete  – moves messages to Recoverable Items (recoverable by admin). DEFAULT.
    HardDelete  – permanently removes messages; not recoverable.

.PARAMETER SearchName
    Name prefix for the Content Search and purge action objects.
    Defaults to "PhishingRemoval_<timestamp>".

.PARAMETER WhatIf
    Show what would be deleted without actually deleting anything.

.EXAMPLE
    # Soft-delete by sender (dry run first)
    .\Remove-PhishingMessages.ps1 -SenderAddress "phish@evil.com" -WhatIf

    # Soft-delete by subject across all mailboxes
    .\Remove-PhishingMessages.ps1 -Subject "Your account has been compromised"

    # Hard-delete by sender + date range
    .\Remove-PhishingMessages.ps1 -SenderAddress "phish@evil.com" `
        -StartDate 2026-03-01 -EndDate 2026-03-18 -PurgeType HardDelete
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Subject,
    [string]$SenderAddress,
    [string]$RecipientAddress,
    [string[]]$BodyKeywords,
    [string]$AttachmentName,
    [string]$MessageId,
    [string]$StartDate,
    [string]$EndDate,
    [ValidateSet('SoftDelete', 'HardDelete')]
    [string]$PurgeType = 'SoftDelete',
    [string]$SearchName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step  { param([string]$Msg) Write-Host "`n[*] $Msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Msg) Write-Host "    [+] $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "    [!] $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "    [-] $Msg" -ForegroundColor Red }

function Assert-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' is not installed. Run: Install-Module $Name -Scope CurrentUser"
    }
}

function Parse-SuccessResults {
    <#
    .SYNOPSIS
        Parses the SuccessResults string from Get-ComplianceSearch into structured objects.
    .DESCRIPTION
        SuccessResults is a raw string where each mailbox entry is separated by a newline,
        and each field within an entry is separated by a semicolon, in "Key: Value" pairs.
        Example entry:
            Location: user@contoso.com; Item count: 3; Total size: 45678; ...
    #>
    param([string]$RawResults)

    if ([string]::IsNullOrWhiteSpace($RawResults)) { return @() }

    $entries = @()

    # Split on newlines; each non-empty line is one mailbox result
    foreach ($line in ($RawResults -split "`r?`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $entry = [PSCustomObject]@{
            Location  = ''
            ItemCount = 0
            TotalSize = 0
        }

        # Each field is "Key: Value" separated by "; "
        foreach ($field in ($line -split ';\s*')) {
            if ($field -match '^(.+?):\s*(.*)$') {
                $key   = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                switch ($key) {
                    'Location'   { $entry.Location  = $value }
                    'Item count' { $entry.ItemCount  = [int]$value }
                    'Total size' { $entry.TotalSize  = [long]$value }
                }
            }
        }

        if ($entry.Location) { $entries += $entry }
    }

    return $entries
}

# ── Validate input ────────────────────────────────────────────────────────────

if (-not ($Subject -or $SenderAddress -or $RecipientAddress -or
          $BodyKeywords -or $AttachmentName -or $MessageId)) {
    throw "Provide at least one search criterion: -Subject, -SenderAddress, -BodyKeywords, -AttachmentName, or -MessageId."
}

Assert-Module 'ExchangeOnlineManagement'

# ── Build KQL query ───────────────────────────────────────────────────────────

Write-Step "Building search query"

$kqlParts = [System.Collections.Generic.List[string]]::new()

if ($Subject)          { $kqlParts.Add("subject:`"$Subject`"") }
if ($SenderAddress)    { $kqlParts.Add("from:$SenderAddress") }
if ($RecipientAddress) { $kqlParts.Add("to:$RecipientAddress") }
if ($AttachmentName)   { $kqlParts.Add("attachment:`"$AttachmentName`"") }
if ($MessageId) {
    $mid = $MessageId.Trim('<>').Trim()
    $kqlParts.Add("header:Message-ID:`"<$mid>`"")
}
foreach ($kw in $BodyKeywords) { $kqlParts.Add("body:`"$kw`"") }
if ($StartDate) { $kqlParts.Add("sent>=$StartDate") }
if ($EndDate)   { $kqlParts.Add("sent<=$EndDate") }

$kqlQuery = $kqlParts -join ' AND '
Write-Ok "KQL Query : $kqlQuery"

# ── Name the search job ───────────────────────────────────────────────────────

if (-not $SearchName) {
    $SearchName = "PhishingRemoval_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
}
$PurgeActionName = "${SearchName}_Purge"

# ── Connect to Security & Compliance ─────────────────────────────────────────

Write-Step "Connecting to Security & Compliance Center"
try {
    # IPPSSession is the compliance endpoint; ExchangeOnlineManagement covers both
    Connect-IPPSSession -ShowBanner:$false -EnableSearchOnlySession
    Write-Ok "Connected"
} catch {
    throw "Failed to connect to Security & Compliance: $_"
}

# ── Create / run Content Search ───────────────────────────────────────────────

Write-Step "Creating Content Search: '$SearchName'"

# Remove stale objects with the same name if they exist
foreach ($existing in (Get-ComplianceSearch -Identity $SearchName -ErrorAction SilentlyContinue)) {
    Write-Warn "Removing existing search with the same name."
    Remove-ComplianceSearch -Identity $SearchName -Confirm:$false
}

$searchParams = @{
    Name                = $SearchName
    ExchangeLocation    = 'All'        # all mailboxes
    ContentMatchQuery   = $kqlQuery
    AllowNotFoundExchangeLocationsEnabled = $true
}
if ($RecipientAddress) {
    $searchParams['ExchangeLocation'] = $RecipientAddress
}

New-ComplianceSearch @searchParams | Out-Null
Write-Ok "Search created. Starting..."

Start-ComplianceSearch -Identity $SearchName

# ── Poll until complete ───────────────────────────────────────────────────────

Write-Step "Waiting for search to complete"
$dots = 0
do {
    Start-Sleep -Seconds 5
    $search = Get-ComplianceSearch -Identity $SearchName
    Write-Host "    Status: $($search.Status)" -NoNewline
    Write-Host (" " * [Math]::Max(0, 20 - $search.Status.Length)) -NoNewline
    $dots++; if ($dots % 10 -eq 0) { Write-Host "" }
} while ($search.Status -notin @('Completed', 'Failed', 'Stopped'))

Write-Host ""

if ($search.Status -ne 'Completed') {
    throw "Search ended with status '$($search.Status)'. Check the Security & Compliance portal."
}

# ── Report results ────────────────────────────────────────────────────────────

Write-Step "Search results"
Write-Ok "Items found : $($search.Items)"
Write-Ok "Size        : $($search.Size) bytes"

if ($search.Items -eq 0) {
    Write-Warn "No matching messages found. Exiting."
    exit 0
}

# Parse the raw SuccessResults string into structured objects, then filter to
# only mailboxes that actually contain matching messages.
$allResults = @(Parse-SuccessResults -RawResults $search.SuccessResults)
$preview    = @($allResults | Where-Object { $_.ItemCount -gt 0 })

Write-Ok "Mailboxes   : $($preview.Count) affected"

if ($preview) {
    Write-Step "Affected mailboxes ($($preview.Count))"
    $preview | ForEach-Object {
        Write-Host ("    {0,-45}  {1} item(s)" -f $_.Location, $_.ItemCount)
    }
}

# ── Confirm before purge ──────────────────────────────────────────────────────

if ($WhatIfPreference) {
    Write-Warn "WhatIf mode: no messages will be deleted."
    Write-Warn "Would delete $($search.Items) item(s) across $($preview.Count) mailbox(es) using $PurgeType."
    exit 0
}

Write-Step "Purge confirmation"
Write-Warn "About to $PurgeType $($search.Items) message(s) from $($preview.Count) mailbox(es)."
if ($PurgeType -eq 'HardDelete') {
    Write-Warn "HARD DELETE is irreversible. Messages cannot be recovered."
}

$answer = Read-Host "    Type 'YES' (all caps) to proceed"
if ($answer -cne 'YES') {
    Write-Warn "Aborted by user."
    exit 0
}

# ── Create purge action ───────────────────────────────────────────────────────

Write-Step "Purging messages ($PurgeType)"

# Remove stale purge action if present
if (Get-ComplianceSearchAction -Identity $PurgeActionName -ErrorAction SilentlyContinue) {
    Remove-ComplianceSearchAction -Identity $PurgeActionName -Confirm:$false
}

New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $PurgeType -Confirm:$false | Out-Null
Write-Ok "Purge action '$PurgeActionName' created. Waiting..."

# ── Poll until purge complete ─────────────────────────────────────────────────

$dots = 0
do {
    Start-Sleep -Seconds 5
    $action = Get-ComplianceSearchAction -Identity $PurgeActionName
    Write-Host "    Status: $($action.Status)" -NoNewline
    Write-Host (" " * [Math]::Max(0, 20 - $action.Status.Length)) -NoNewline
    $dots++; if ($dots % 10 -eq 0) { Write-Host "" }
} while ($action.Status -notin @('Completed', 'Failed', 'Stopped'))

Write-Host ""

if ($action.Status -ne 'Completed') {
    throw "Purge action ended with status '$($action.Status)'. Review in the Security & Compliance portal."
}

# ── Final report ──────────────────────────────────────────────────────────────

Write-Step "Done"
Write-Ok "Purge type   : $PurgeType"
Write-Ok "Items purged : $($search.Items)"
Write-Ok "Search name  : $SearchName"
Write-Ok "Action name  : $PurgeActionName"

if ($PurgeType -eq 'SoftDelete') {
    Write-Host "`n    Messages moved to 'Recoverable Items'. Admins can restore via" -ForegroundColor Gray
    Write-Host "    Search-Mailbox or eDiscovery if needed." -ForegroundColor Gray
} else {
    Write-Host "`n    Messages permanently deleted." -ForegroundColor Gray
}

Write-Host ""
