# Verify that the required .NET runtime is available before loading the binary module.
# This script runs in the caller's scope via ScriptsToProcess in the module manifest.
$required = 9
$actual   = [System.Environment]::Version.Major

if ($actual -lt $required) {
    throw (
        "Send-MailKitMessage requires .NET $required or later (PowerShell 7.5 or later). " +
        "Detected: .NET $actual (PowerShell $($PSVersionTable.PSVersion)). " +
        "Download the latest PowerShell at https://aka.ms/powershell"
    )
}
