# Send-MailKitMessage

A replacement for PowerShell's [obsolete Send-MailMessage](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.1#description) implementing the [Microsoft-recommended MailKit library](https://docs.microsoft.com/en-us/dotnet/api/system.net.mail.smtpclient?view=net-5.0#remarks).

- [Installation](#installation)
- [Usage](#usage)
    - [Basic](#basic)
    - [All Parameters](#all-parameters)
- [Releases](#releases)

# <a id="installation" />Installation  

**For current user only** (does not require elevated privileges):<br />
```Install-Module -Name "Send-MailKitMessage" -Scope CurrentUser```  

**For all users** (requires elevated privileges):<br />
```Install-Module -Name "Send-MailKitMessage" -Scope AllUsers```  

# <a id="usage" />Usage

### Basic

```powershell
Import-Module Send-MailKitMessage;

#SMTP server ([string], required)
$SMTPServer = "SMTPServer";

#port ([int], required)
$Port = 587;

#sender ([string], required)
$From = "sender@example.com";

#recipient(s) ([string] or [string[]], required)
#aliases: ToList, RecipientList
$To = "recipient@example.com";
# $To = @("recipient1@example.com", "recipient2@example.com");

#subject ([string], optional)
$Subject = "Subject";

#text body ([string], optional)
$TextBody = "TextBody";

#send message
Send-MailKitMessage -SMTPServer $SMTPServer -Port $Port -From $From -To $To -Subject $Subject -TextBody $TextBody;
```

### All Parameters

```powershell
Import-Module Send-MailKitMessage;

#use secure connection if available ([switch], optional, default: enabled)
##aliases: UseSSLIfAvailable, UseSecureConnectionIfAvailable
$UseSSL = $true;

#authentication ([System.Management.Automation.PSCredential], optional)
$Credential = Get-Credential;

#SMTP server ([string], required)
$SMTPServer = "smtp.example.com";

#port ([int], required)
$Port = 587;

#sender ([string], required)
$From = "sender@example.com";

#recipient(s) ([string] or [string[]], required)
##aliases: ToList, RecipientList
$To = "recipient@example.com";
# $To = @("recipient1@example.com", "recipient2@example.com");

#CC recipient(s) ([string] or [string[]], optional)
##aliases: CCList, CarbonCopyList
$CC = "cc@example.com";
# $CC = @("cc1@example.com", "cc2@example.com");

#BCC recipient(s) ([string] or [string[]], optional)
##aliases: BCCList, BlindCarbonCopyList
$BCC = "bcc@example.com";
# $BCC = @("bcc1@example.com", "bcc2@example.com");

#reply-to address(es) ([string] or [string[]], optional)
$ReplyTo = "replyto@example.com";
# $ReplyTo = @("replyto1@example.com", "replyto2@example.com");

#subject ([string], optional)
$Subject = "Subject";

#text body ([string], optional)
##aliases: Body
$TextBody = "TextBody";

#HTML body ([string], optional)
##aliases: BodyAsHtml
$HTMLBody = "<b>HTMLBody</b>";

#attachment(s) ([string[]], optional)
$AttachmentList = @("C:\path\to\file1.txt", "C:\path\to\file2.pdf");

#sign email with S/MIME ([switch], optional)
$SignMail = $true;

#S/MIME certificate for signing or encrypting ([System.Security.Cryptography.X509Certificates.X509Certificate2], optional)
##aliases: X509MailCertificate, SMimeCert
$SMimeCertificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq "CERTTHUMBPRINT";

#digest algorithm for S/MIME signing ([MimeKit.Cryptography.DigestAlgorithm], optional, default: Sha256)
#available values: Sha256, Sha384, Sha512, etc. (MD5, Sha1 and other weak algorithms are automatically upgraded to Sha256)
$SigningAlgorithm = [MimeKit.Cryptography.DigestAlgorithm]::Sha256;

#client certificates for SSL/TLS handshake ([System.Security.Cryptography.X509Certificates.X509Certificate2[]], optional)
$ClientCertificates = @(Get-ChildItem Cert:\[...] | Where-Object Thumbprint -eq "CLIENTCERTTHUMBPRINT");

#disable certificate revocation checking during SSL/TLS handshake ([switch], optional)
$DisableCertificateRevocation = $true;

#accept all server certificates regardless of validation errors ([switch], optional, not recommended in production)
$ServerCertificateValidationCallback = $true;

#simulate the operation without actually sending ([switch], optional)
$WhatIf = $true;

#splat parameters
$Parameters = @{
    UseSSL                              = $UseSSL
    Credential                          = $Credential
    SMTPServer                          = $SMTPServer
    Port                                = $Port
    From                                = $From
    To                                  = $To
    CC                                  = $CC
    BCC                                 = $BCC
    ReplyTo                             = $ReplyTo
    Subject                             = $Subject
    TextBody                            = $TextBody
    HTMLBody                            = $HTMLBody
    AttachmentList                      = $AttachmentList
    SignMail                            = $SignMail
    SMimeCertificate                    = $SMimeCertificate
    SigningAlgorithm                    = $SigningAlgorithm
    ClientCertificates                  = $ClientCertificates
    DisableCertificateRevocation        = $DisableCertificateRevocation
    ServerCertificateValidationCallback = $ServerCertificateValidationCallback
    WhatIf                              = $WhatIf
};

#send message
Send-MailKitMessage @Parameters;
```

# <a id="releases" />Releases

### 3.2.0

- Add support for Windows PowerShell

### 3.2.0-preview1

- Add support for Windows PowerShell

### 3.1.0

- Changed UseSecureConnectionIfAvailable parameter type from [bool] to [switch]

### 3.0.0

- Added credential support

- Added parameter to use secure connection if available
- Removed extended classes
- Changed ToList parameter to RecipientList
- Properly return exceptions from the module to the caller
- Switched from BouncyCastle to Portable.BouncyCastle
- Updated MailKit to 2.10.1
- Updated MimeKit to 2.10.1
