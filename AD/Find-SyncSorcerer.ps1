Import-Module ActiveDirectory

# === GUIDs for replication rights ===
$replicationRights = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # Replicating Directory Changes
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",  # Replicating Directory Changes All
    "89e95b76-444d-4c62-991a-0facbeda640c"   # Replicating Directory Changes in Filtered Set
)

# === Domain ACL ===
$domainDN = (Get-ADDomain).DistinguishedName
$domainObject = [ADSI]"LDAP://$domainDN"
$acl = $domainObject.psbase.ObjectSecurity.Access

# === Result containers ===
$directUsers = @()
$groupMemberships = @{}
$unresolvedSIDs = @()
$globalUserSet = New-Object System.Collections.Generic.HashSet[string]

# === Resolve SID or name ===
function Resolve-NTAccount {
    param($identity)
    try {
        if ($identity -match "^S-1-") {
            $ntAccount = (New-Object System.Security.Principal.SecurityIdentifier($identity)).Translate([System.Security.Principal.NTAccount])
            return $ntAccount.Value
        } else {
            return $identity
        }
    } catch {
        return $null
    }
}

function Get-AllUserMembers {
    param (
        [string]$GroupDN,
        [ref]$Visited
    )

    $results = @()
    if ($Visited.Value.Contains($GroupDN)) { return @() }
    $Visited.Value.Add($GroupDN) | Out-Null

    try {
        $members = Get-ADGroupMember -Identity $GroupDN -ErrorAction Stop
        foreach ($member in $members) {
            if ($member.objectClass -in @('user', 'computer')) {
                # Add member regardless of global deduplication
                $results += $member.SamAccountName
            } elseif ($member.objectClass -eq 'group') {
                $results += Get-AllUserMembers -GroupDN $member.DistinguishedName -Visited $Visited
            }
        }
    } catch {}
    return ,$results
}



# === Process ACL entries ===
foreach ($ace in $acl) {
    $guid = $ace.ObjectType.Guid.ToString().ToLower()
    if ($replicationRights -notcontains $guid -or $ace.AccessControlType -ne 'Allow') { continue }

    $rawIdentity = $ace.IdentityReference.Value
    $resolvedIdentity = Resolve-NTAccount $rawIdentity
    $identityName = if ($resolvedIdentity) { $resolvedIdentity } else { $rawIdentity }
    $sam = $identityName.Split('\')[-1]

    # Try user
    try {
        $user = Get-ADUser -Identity $sam -ErrorAction Stop
        if ($globalUserSet.Add($user.SamAccountName)) {
            $directUsers += $user.SamAccountName
        }
        continue
    } catch {}

    # Try Computer 
    try {
    $computer = Get-ADComputer -Identity $sam -ErrorAction Stop
    if ($globalUserSet.Add($computer.SamAccountName)) {
        $directUsers += $computer.SamAccountName
    }
    continue
} catch {}

    # Try group
    try {
        $group = Get-ADGroup -Identity $sam -ErrorAction Stop
        $visited = New-Object System.Collections.Generic.HashSet[string]
        $members = Get-AllUserMembers -GroupDN $group.DistinguishedName -Visited ([ref]$visited)
        if (-not $groupMemberships.ContainsKey($identityName)) {
            $groupMemberships[$identityName] = $members
        }
        continue
    } catch {}

    # If not resolvable
    if (-not $resolvedIdentity) {
        $unresolvedSIDs += $rawIdentity
    }
}

# === OUTPUT ===
Write-Host "Following User have the Replicating Directory Changes, Replicating Directory Changes All or Replicating Directory Changes in Filtered Set permission" -ForegroundColor Gray
Write-Host "`n[Directly Permissioned Users]" -ForegroundColor Cyan
$directUsers | Sort-Object | ForEach-Object {
    Write-Host "- $_"
}

foreach ($group in $groupMemberships.Keys) {
    Write-Host "`n[Members of Group: $group]" -ForegroundColor Yellow
    $members = $groupMemberships[$group] | Sort-Object -Unique
    if ($members.Count -eq 0) {
        Write-Host "  (no user members found)"
    } else {
        $members | Sort-Object | ForEach-Object {
            Write-Host "  - $_"
        }
    }
}

if ($unresolvedSIDs.Count -gt 0) {
    Write-Host "`n[Unresolved SIDs or Identities]" -ForegroundColor Red
    $unresolvedSIDs | Sort-Object | ForEach-Object {
        Write-Host "- $_"
    }
}
