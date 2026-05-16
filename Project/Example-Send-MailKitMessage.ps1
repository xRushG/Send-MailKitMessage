Import-Module "$PSScriptRoot\Send-MailKitMessage.psd1" -Force

$SMTPServer  = ""
$Port        = 587
$From        = ""
$To          = @("")
$CC          = @("")
$BCC         = @("")
$Subject     = "Send-MailKitMessage Test E-Mail"
$TextBody    = "Test Text for Test Mails"
$HTMLBody    = ""
$Attachments = @("")
$Credential  = Get-Credential -UserName "" -Message "Enter your Account Password"
$Cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq 'CERTTHUMBPRINT'

Send-MailKitMessage `
    -SMTPServer $SMTPServer -Port $Port `
    -From $From -To $To `
    -Subject $Subject -Body $TextBody `
    -Credential $Credential `
    -UseSSL `
    -SignMail -SMimeCertificate $Cert

