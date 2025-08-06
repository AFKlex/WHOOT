# Set up variables
$hostname = $env:COMPUTERNAME
$scriptName = "ADBadPwdMonitor"
$logPath = ".\BadPasswordCollisions.log"
$limit = 10  #more user need the same time on the second 

# Get current timestamp in syslog format
$runTime = Get-Date
$syslogTime = $runTime.ToString("MMM dd HH:mm:ss")

# Log script execution
Add-Content -Path $logPath -Value "$syslogTime $hostname $($scriptName): Script execution started"

# Fetch and filter users with LastBadPasswordAttempt set
$users = Get-ADUser -Filter * -Properties LastBadPasswordAttempt,BadPwdCount |
    Where-Object { $_.LastBadPasswordAttempt } |
    Select-Object Name, LastBadPasswordAttempt, BadPwdCount |
    Sort-Object LastBadPasswordAttempt

# Group by precise timestamp (to the second)
$grouped = $users | Group-Object { $_.LastBadPasswordAttempt.ToString("yyyy-MM-dd HH:mm:ss") }

# Detect potential spraying and log events
foreach ($group in $grouped) {
    if ($group.Count -ge $limit) {
        $eventTime = [datetime]::ParseExact($group.Name, "yyyy-MM-dd HH:mm:ss", $null)
        $eventSyslogTime = $eventTime.ToString("MMM dd HH:mm:ss")

        $message = "$eventSyslogTime $hostname $($scriptName): Possible password spraying detected - $($group.Count) users at $($group.Name)"
        Add-Content -Path $logPath -Value $message

        foreach ($user in $group.Group) {
            $userLog = "$eventSyslogTime $hostname $($scriptName):    User: $($user.Name)"
            Add-Content -Path $logPath -Value $userLog
        }

        Add-Content -Path $logPath -Value ""  # Blank line between incidents
    }
}

Add-Content -Path $logPath -Value "$syslogTime $hostname $($scriptName): Script execution completed"
