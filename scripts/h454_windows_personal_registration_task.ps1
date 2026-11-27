param(
    [Parameter(Mandatory)][ValidateSet('Check','Stop','Start')][string]$Mode,
    [Parameter(Mandatory)][string]$ExpectedExecutable,
    [Parameter(Mandatory)][string]$ExpectedArguments,
    [Parameter(Mandatory)][string]$ExpectedSid,
    [Parameter(Mandatory)][string]$BootstrapDigest
)
$ErrorActionPreference = 'Stop'
$taskName = 'HermesCommanderYfcPersonal'
function Resolve-TaskSid([string]$value) {
    if ($value -match '^S-1-[0-9-]+$') { return $value }
    return ([System.Security.Principal.NTAccount]::new($value)).Translate([System.Security.Principal.SecurityIdentifier]).Value
}
function CheckedTask {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $ExpectedExecutable -or
        $task.Actions[0].Arguments -cne $ExpectedArguments -or @($task.Triggers).Count -ne 1 -or
        (Resolve-TaskSid $task.Triggers[0].UserId) -cne $ExpectedSid -or
        (Resolve-TaskSid $task.Principal.UserId) -cne $ExpectedSid -or
        $task.Principal.LogonType -ne 'Interactive' -or $task.Principal.RunLevel -ne 'Limited' -or
        $task.Settings.Enabled -ne $true) { throw 'TASK_IDENTITY_MISMATCH' }
    return $task
}
$task = CheckedTask
switch ($Mode) {
    'Check' { if ($task.State -ne 'Running') { throw 'TASK_NOT_RUNNING' } }
    'Stop' {
        if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop }
        $deadline = (Get-Date).AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 300
            $task = CheckedTask
            $filter = "Name = 'pythonw.exe' AND CommandLine LIKE '%$BootstrapDigest%'"
            $processes = @(Get-CimInstance Win32_Process -Filter $filter)
            if ($task.State -ne 'Running' -and $processes.Count -eq 0) { break }
        } while ((Get-Date) -lt $deadline)
        if ($task.State -eq 'Running' -or $processes.Count -ne 0) { throw 'TASK_DID_NOT_STOP' }
    }
    'Start' {
        if ($task.State -ne 'Running') { Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop }
        $deadline = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 300
            $task = CheckedTask
            if ($task.State -eq 'Running') { break }
        } while ((Get-Date) -lt $deadline)
        if ($task.State -ne 'Running') { throw 'TASK_DID_NOT_START' }
    }
}
Write-Output ('TASK_CONTROL_' + $Mode + '=PASS')
