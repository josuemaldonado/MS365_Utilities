#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Groups, Microsoft.Graph.Users

<#
.SYNOPSIS
    Export all members of every group in Microsoft 365 to a CSV report.

.DESCRIPTION
    Connects to Exchange Online and Microsoft Graph, then enumerates every group
    type in the tenant:

        - Microsoft 365 Groups (Unified)
        - Distribution Lists
        - Mail-Enabled Security Groups
        - Security Groups (Azure AD / Entra ID, cloud-only and synced)

    For each group every member is written as a flat row, so the resulting CSV
    can be filtered, sorted, or pivoted in Excel / Power BI without any further
    transformation.

    Required permissions (least-privilege):
        - Exchange Online: View-Only Recipients  (for EXO group cmdlets)
        - Microsoft Graph: Group.Read.All, User.Read.All, GroupMember.Read.All

.PARAMETER OutputPath
    Full path for the CSV output file.
    Default: .\MS365_GroupMembers_<timestamp>.csv in the current directory.

.PARAMETER ExchangeOrganization
    The .onmicrosoft.com domain used to connect to Exchange Online.
    If omitted the cmdlet will prompt for credentials interactively.

.PARAMETER SkipExchangeGroups
    Switch. Skip Distribution Lists and Mail-Enabled Security Groups.
    Use when the account has Graph permissions but no Exchange Online access.

.PARAMETER SkipSecurityGroups
    Switch. Skip Azure AD / Entra ID security groups (Graph only, non-mail-enabled).

.EXAMPLE
    .\Get-AllGroupMembers.ps1
    Connects interactively, queries all group types, and saves a CSV to the
    current directory.

.EXAMPLE
    .\Get-AllGroupMembers.ps1 -OutputPath "C:\Reports\GroupMembers.csv" `
        -ExchangeOrganization "contoso.onmicrosoft.com"

.NOTES
    Install required modules (once, as admin):
        Install-Module ExchangeOnlineManagement -Scope CurrentUser
        Install-Module Microsoft.Graph -Scope CurrentUser
#>

[CmdletBinding()]
param (
    [string]  $OutputPath            = "",
    [string]  $ExchangeOrganization  = "",
    [switch]  $SkipExchangeGroups,
    [switch]  $SkipSecurityGroups
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── Helpers ──────────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Write-Done {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Warning "[$(Get-Date -Format 'HH:mm:ss')] $Message"
}

# Build a standardised row object
function New-MemberRow {
    param(
        [string]$GroupName,
        [string]$GroupEmail,
        [string]$GroupType,
        [string]$MemberDisplayName,
        [string]$MemberEmail,
        [string]$MemberUPN,
        [string]$MemberType,       # User | Group | Contact | Unknown
        [string]$MemberObjectId
    )
    [PSCustomObject]@{
        GroupName         = $GroupName
        GroupEmail        = $GroupEmail
        GroupType         = $GroupType
        MemberDisplayName = $MemberDisplayName
        MemberEmail       = $MemberEmail
        MemberUPN         = $MemberUPN
        MemberType        = $MemberType
        MemberObjectId    = $MemberObjectId
    }
}

#endregion

#region ── Output path ──────────────────────────────────────────────────────────

if (-not $OutputPath) {
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path (Get-Location).Path "MS365_GroupMembers_$timestamp.csv"
}

$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

#endregion

#region ── Connect ──────────────────────────────────────────────────────────────

Write-Step "Connecting to Microsoft Graph..."
$graphScopes = @(
    "Group.Read.All"
    "GroupMember.Read.All"
    "User.Read.All"
)
Connect-MgGraph -Scopes $graphScopes -NoWelcome

if (-not $SkipExchangeGroups) {
    Write-Step "Connecting to Exchange Online..."
    $exoParams = @{ ShowBanner = $false }
    if ($ExchangeOrganization) { $exoParams.Organization = $ExchangeOrganization }
    Connect-ExchangeOnline @exoParams
}

#endregion

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

#region ── 1. Microsoft 365 Groups (Unified) via Graph ──────────────────────────

Write-Step "Fetching Microsoft 365 Groups (Unified)..."

$m365Groups = @(Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified')" `
    -Property "Id,DisplayName,Mail" -All -PageSize 999)

Write-Done "Found $($m365Groups.Count) M365 Groups."

foreach ($group in $m365Groups) {
    Write-Verbose "  Processing M365 Group: $($group.DisplayName)"

    $members = @(Get-MgGroupMember -GroupId $group.Id -All -PageSize 999)

    if ($members.Count -eq 0) {
        $report.Add((New-MemberRow `
            -GroupName        $group.DisplayName `
            -GroupEmail       $group.Mail `
            -GroupType        "Microsoft 365 Group" `
            -MemberDisplayName "(no members)" `
            -MemberEmail      "" `
            -MemberUPN        "" `
            -MemberType       "" `
            -MemberObjectId   ""))
        continue
    }

    foreach ($member in $members) {
        $odataType = $member.AdditionalProperties["@odata.type"] ?? ""
        $displayName = $member.AdditionalProperties["displayName"] ?? ""
        $mail        = $member.AdditionalProperties["mail"] ?? ""
        $upn         = $member.AdditionalProperties["userPrincipalName"] ?? ""

        $memberType = switch -Wildcard ($odataType) {
            "*user"    { "User" }
            "*group"   { "Group" }
            "*contact" { "Contact" }
            default    { "Unknown" }
        }

        $report.Add((New-MemberRow `
            -GroupName        $group.DisplayName `
            -GroupEmail       $group.Mail `
            -GroupType        "Microsoft 365 Group" `
            -MemberDisplayName $displayName `
            -MemberEmail      $mail `
            -MemberUPN        $upn `
            -MemberType       $memberType `
            -MemberObjectId   $member.Id))
    }
}

#endregion

#region ── 2. Distribution Lists via Exchange Online ────────────────────────────

if (-not $SkipExchangeGroups) {
    Write-Step "Fetching Distribution Lists..."

    $distGroups = @(Get-DistributionGroup -ResultSize Unlimited -RecipientTypeDetails MailUniversalDistributionGroup)

    Write-Done "Found $($distGroups.Count) Distribution Lists."

    foreach ($group in $distGroups) {
        Write-Verbose "  Processing DL: $($group.DisplayName)"

        $members = @(Get-DistributionGroupMember -Identity $group.Identity -ResultSize Unlimited)

        if ($members.Count -eq 0) {
            $report.Add((New-MemberRow `
                -GroupName        $group.DisplayName `
                -GroupEmail       $group.PrimarySmtpAddress `
                -GroupType        "Distribution List" `
                -MemberDisplayName "(no members)" `
                -MemberEmail      "" `
                -MemberUPN        "" `
                -MemberType       "" `
                -MemberObjectId   ""))
            continue
        }

        foreach ($member in $members) {
            $memberType = switch ($member.RecipientTypeDetails) {
                { $_ -like "*UserMailbox*" }          { "User" }
                { $_ -like "*MailContact*" }           { "Contact" }
                { $_ -like "*MailUniversal*" }         { "Group" }
                { $_ -like "*Group*" }                 { "Group" }
                default                                { $member.RecipientTypeDetails }
            }

            $report.Add((New-MemberRow `
                -GroupName        $group.DisplayName `
                -GroupEmail       $group.PrimarySmtpAddress `
                -GroupType        "Distribution List" `
                -MemberDisplayName $member.DisplayName `
                -MemberEmail      $member.PrimarySmtpAddress `
                -MemberUPN        $member.WindowsLiveID `
                -MemberType       $memberType `
                -MemberObjectId   $member.ExternalDirectoryObjectId))
        }
    }

    #endregion

    #region ── 3. Mail-Enabled Security Groups via Exchange Online ──────────────────

    Write-Step "Fetching Mail-Enabled Security Groups..."

    $mailSecGroups = @(Get-DistributionGroup -ResultSize Unlimited -RecipientTypeDetails MailUniversalSecurityGroup)

    Write-Done "Found $($mailSecGroups.Count) Mail-Enabled Security Groups."

    foreach ($group in $mailSecGroups) {
        Write-Verbose "  Processing MESG: $($group.DisplayName)"

        $members = @(Get-DistributionGroupMember -Identity $group.Identity -ResultSize Unlimited)

        if ($members.Count -eq 0) {
            $report.Add((New-MemberRow `
                -GroupName        $group.DisplayName `
                -GroupEmail       $group.PrimarySmtpAddress `
                -GroupType        "Mail-Enabled Security Group" `
                -MemberDisplayName "(no members)" `
                -MemberEmail      "" `
                -MemberUPN        "" `
                -MemberType       "" `
                -MemberObjectId   ""))
            continue
        }

        foreach ($member in $members) {
            $memberType = switch ($member.RecipientTypeDetails) {
                { $_ -like "*UserMailbox*" }  { "User" }
                { $_ -like "*MailContact*" }   { "Contact" }
                { $_ -like "*Group*" }         { "Group" }
                default                        { $member.RecipientTypeDetails }
            }

            $report.Add((New-MemberRow `
                -GroupName        $group.DisplayName `
                -GroupEmail       $group.PrimarySmtpAddress `
                -GroupType        "Mail-Enabled Security Group" `
                -MemberDisplayName $member.DisplayName `
                -MemberEmail      $member.PrimarySmtpAddress `
                -MemberUPN        $member.WindowsLiveID `
                -MemberType       $memberType `
                -MemberObjectId   $member.ExternalDirectoryObjectId))
        }
    }
}

#endregion

#region ── 4. Security Groups (non-mail-enabled) via Graph ──────────────────────

if (-not $SkipSecurityGroups) {
    Write-Step "Fetching Security Groups (non-mail-enabled) via Graph..."

    # Filter: securityEnabled=true AND NOT a Unified (M365) group AND NOT mail-enabled
    $secGroups = @(Get-MgGroup `
        -Filter "securityEnabled eq true and mailEnabled eq false" `
        -Property "Id,DisplayName,Mail,GroupTypes" `
        -All -PageSize 999 |
        Where-Object { $_.GroupTypes -notcontains "Unified" })

    Write-Done "Found $($secGroups.Count) Security Groups."

    foreach ($group in $secGroups) {
        Write-Verbose "  Processing Security Group: $($group.DisplayName)"

        $members = @(Get-MgGroupMember -GroupId $group.Id -All -PageSize 999)

        if ($members.Count -eq 0) {
            $report.Add((New-MemberRow `
                -GroupName        $group.DisplayName `
                -GroupEmail       $group.Mail `
                -GroupType        "Security Group" `
                -MemberDisplayName "(no members)" `
                -MemberEmail      "" `
                -MemberUPN        "" `
                -MemberType       "" `
                -MemberObjectId   ""))
            continue
        }

        foreach ($member in $members) {
            $odataType   = $member.AdditionalProperties["@odata.type"] ?? ""
            $displayName = $member.AdditionalProperties["displayName"] ?? ""
            $mail        = $member.AdditionalProperties["mail"] ?? ""
            $upn         = $member.AdditionalProperties["userPrincipalName"] ?? ""

            $memberType = switch -Wildcard ($odataType) {
                "*user"    { "User" }
                "*group"   { "Group" }
                "*device"  { "Device" }
                "*contact" { "Contact" }
                default    { "Unknown" }
            }

            $report.Add((New-MemberRow `
                -GroupName        $group.DisplayName `
                -GroupEmail       ($group.Mail ?? "") `
                -GroupType        "Security Group" `
                -MemberDisplayName $displayName `
                -MemberEmail      $mail `
                -MemberUPN        $upn `
                -MemberType       $memberType `
                -MemberObjectId   $member.Id))
        }
    }
}

#endregion

#region ── Export ───────────────────────────────────────────────────────────────

Write-Step "Exporting $($report.Count) rows to: $OutputPath"

$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Done "Report saved to: $OutputPath"

# Summary breakdown
$summary = $report |
    Where-Object { $_.MemberDisplayName -ne "(no members)" } |
    Group-Object GroupType |
    Select-Object Name, Count |
    Sort-Object Name

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Yellow
$summary | Format-Table -AutoSize
Write-Host "Total member rows: $(($report | Where-Object { $_.MemberDisplayName -ne '(no members)' }).Count)" -ForegroundColor Yellow

#endregion

#region ── Disconnect ───────────────────────────────────────────────────────────

if (-not $SkipExchangeGroups) {
    Disconnect-ExchangeOnline -Confirm:$false
}
Disconnect-MgGraph | Out-Null

#endregion
