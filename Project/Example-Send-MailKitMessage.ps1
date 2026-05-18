Import-Module "$PSScriptRoot\Send-MailKitMessage.psd1" -Force

# ─── Connection ───────────────────────────────────────────────────────────────

# SMTP server address ([string], required)
# Parameter: -SMTPServer
$SMTPServer = "smtp.example.com"

# SMTP port ([int], required) — common values: 25 (unencrypted), 587 (STARTTLS), 465 (SSL)
# Parameter: -Port
$Port = 587

# ─── Security ─────────────────────────────────────────────────────────────────

# Use a secure connection (SSL/TLS) if available ([switch], optional, default: enabled)
# Parameter: -UseSSL  |  Aliases: -UseSSLIfAvailable, -UseSecureConnectionIfAvailable
$UseSSL = $true

# SMTP authentication credentials ([PSCredential], optional)
# Parameter: -Credential
$Credential = Get-Credential -UserName "" -Message "Enter your SMTP account password"

# ─── Sender & Recipients ──────────────────────────────────────────────────────

# Sender address ([string], required)
# Parameter: -From
$From = "sender@example.com"

# Primary recipient(s) ([string] or [string[]], required)
# Parameter: -To  |  Aliases: -ToList, -RecipientList
$To = "recipient@example.com"
# $To = @("recipient1@example.com", "recipient2@example.com")

# Carbon copy recipient(s) ([string] or [string[]], optional)
# Parameter: -CC  |  Aliases: -CCList, -CarbonCopyList
$CC = @()
# $CC = "cc@example.com"
# $CC = @("cc1@example.com", "cc2@example.com")

# Blind carbon copy recipient(s) ([string] or [string[]], optional)
# Parameter: -BCC  |  Aliases: -BCCList, -BlindCarbonCopyList
$BCC = @()
# $BCC = "bcc@example.com"
# $BCC = @("bcc1@example.com", "bcc2@example.com")

# Reply-to address(es) ([string] or [string[]], optional)
# Parameter: -ReplyTo
$ReplyTo = @()
# $ReplyTo = "replyto@example.com"
# $ReplyTo = @("replyto1@example.com", "replyto2@example.com")

# ─── Message ──────────────────────────────────────────────────────────────────

# Subject line ([string], optional)
# Parameter: -Subject
$Subject = "Send-MailKitMessage Example"

# Email priority ([string], optional) — accepted values: Low, Normal, High
# Parameter: -Priority
$Priority = "Normal"

# Plain text body ([string], optional)
# Parameter: -TextBody  |  Alias: -Body
$TextBody = "This is a test email sent via Send-MailKitMessage."

# HTML body ([string], optional) — HTML entities are decoded automatically before sending
# Parameter: -HTMLBody  |  Alias: -BodyAsHtml
$HTMLBody = ""
# $HTMLBody = "<b>This is a <i>test</i> email.</b>"

# Attachment(s) — full file path(s) ([string] or [string[]], optional)
# Parameter: -Attachment  |  Aliases: -Attachments, -AttachmentList
$Attachment = @()
# $Attachment = "C:\path\to\file.txt"
# $Attachment = @("C:\path\to\file1.txt", "C:\path\to\file2.pdf")

# ─── S/MIME Signing ───────────────────────────────────────────────────────────

# Sign the email with S/MIME ([switch], optional)
# Parameter: -SignMail
$SignMail = $false

# S/MIME signing certificate ([X509Certificate2], required when -SignMail is used)
# Parameter: -SMimeCertificate  |  Aliases: -X509MailCertificate, -SMimeCert
$SMimeCertificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq "CERTTHUMBPRINT"

# Digest algorithm for S/MIME signing ([DigestAlgorithm], optional, default: Sha256)
# Accepted values: Sha256, Sha384, Sha512 — weak algorithms (MD5, Sha1, RipeMD160) are upgraded to Sha256 automatically
# Parameter: -SigningAlgorithm
$SigningAlgorithm = [MimeKit.Cryptography.DigestAlgorithm]::Sha256

# ─── Advanced SSL/TLS ─────────────────────────────────────────────────────────

# Client certificates for mutual TLS authentication ([X509Certificate2[]], optional)
# Parameter: -ClientCertificates
$ClientCertificates = @()
# $ClientCertificates = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq "CLIENTCERTTHUMBPRINT")

# Disable certificate revocation checking during SSL/TLS handshake ([switch], optional)
# Parameter: -DisableCertificateRevocation
$DisableCertificateRevocation = $false

# Accept all server certificates regardless of validation errors ([switch], optional)
# Warning: disables certificate validation — do not use in production
# Parameter: -ServerCertificateValidationCallback
$ServerCertificateValidationCallback = $false

# ─── Other ────────────────────────────────────────────────────────────────────

# Simulate sending without actually delivering the email ([switch], optional)
# Parameter: -WhatIf
$WhatIf = $false

# ─── Send ─────────────────────────────────────────────────────────────────────

Send-MailKitMessage `
    -SMTPServer $SMTPServer -Port $Port `
    -UseSSL:$UseSSL `
    -Credential $Credential `
    -From $From -To $To `
    -Subject $Subject -TextBody $TextBody
