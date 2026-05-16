using MimeKit;
using System.Management.Automation;
using System.Web;
using System.Security.Cryptography.X509Certificates;
using MimeKit.Cryptography;
using System;
using System.Security.Authentication;
using MailKit.Net.Smtp;

namespace Send_MailKitMessage
{
    [Cmdlet(VerbsCommunications.Send, "MailKitMessage")]
    [Alias("Send-PSMailMessage")]
    [OutputType(typeof(void))]
    public class SendMailKitMessage : PSCmdlet
    {
        #region powershell parameter

        /// <summary>
        /// If specified, method will use a secure connection if available.
        /// </summary>
        [Parameter(
            Mandatory = false,
            HelpMessage = "Use this switch to enable a secure connection (SSL/TLS) if it is available."
        )]
        [Alias("UseSSLIfAvailable", "UseSecureConnectionIfAvailable")]
        public SwitchParameter UseSSL { get; set; } = SwitchParameter.Present;

        /// <summary>
        /// The PSCredential object that contains the credentials to use for SMTP authentication.
        /// </summary>
        [Parameter(
            Mandatory = false,
            HelpMessage = "Provide the PSCredential object containing the username and password for SMTP authentication."
        )]
        public PSCredential Credential { get; set; }

        /// <summary>
        /// The address of the SMTP server to use for sending the email.
        /// </summary>
        [Parameter(
            Mandatory = true,
            HelpMessage = "Specify the SMTP server address (e.g., smtp.example.com) used for sending emails."
        )]
        public string SMTPServer { get; set; }

        /// <summary>
        /// The port number on the SMTP server to connect to.
        /// </summary>
        [Parameter(
            Mandatory = true,
            HelpMessage = "Specify the port number on the SMTP server (e.g., 25, 587, or 465)."
        )]
        public int Port { get; set; }

        /// <summary>
        /// The mailbox address from which the email will be sent.
        /// </summary>
        [Parameter(
            Mandatory = true,
            HelpMessage = "Specify the sender's mailbox address (e.g., sender@example.com)."
        )]
        public string From { get; set; }

        /// <summary>
        /// A list of recipient email addresses.
        /// </summary>
        [Parameter(
            Mandatory = true,
            HelpMessage = "Provide a list of recipient email addresses (e.g., recipient1@example.com, recipient2@example.com)."
        )]
        [Alias("ToList", "RecipientList")]
        public string[] To { get; set; }

        /// <summary>
        /// A list of CC (carbon copy) recipient email addresses.
        /// </summary>
        [Parameter(
            Mandatory = false,
            HelpMessage = "Optionally provide a list of CC recipients' email addresses."
        )]
        [Alias("CCList", "CarbonCopyList")]
        public string[] CC { get; set; }

        /// <summary>
        /// A list of BCC (blind carbon copy) recipient email addresses.
        /// </summary>
        [Parameter(
            Mandatory = false,
            HelpMessage = "Optionally provide a list of BCC recipients' email addresses."
        )]
        [Alias("BCCList", "BlindCarbonCopyList")]
        public string[] BCC { get; set; }

        /// <summary>
        /// The mailbox address to which replies should be sent.
        /// </summary>
        [Parameter(
            Mandatory = false,
            HelpMessage = "Specify the reply-to email address (e.g., replyto@example.com)."
        )]
        public string[] ReplyTo { get; set; }

        /// <summary>
        /// The subject of the email.
        /// </summary>
        [Parameter(
           Mandatory = false,
           HelpMessage = "Specify the subject line for the email."
        )]

        public string Subject { get; set; }

        /// <summary>
        /// The plain text body of the email.
        /// </summary>
        [Parameter(
           Mandatory = false,
           HelpMessage = "Provide the plain text body content for the email."
        )]
        [Alias("Body")]
        public string TextBody { get; set; }

        /// <summary>
        /// The HTML body of the email.
        /// </summary>
        [Parameter(
           Mandatory = false,
           HelpMessage = "Provide HTML formatted content as the body of your email."
        )]
        [Alias("BodyAsHtml")]
        public string HTMLBody { get; set; }

        /// <summary>
        /// An array of file paths for attachments to include in the email.
        /// </summary>
        [Parameter(
           Mandatory = false,
           HelpMessage = "Optionally specify an array of file paths for attachments to include with your email."
        )]
        public string[] AttachmentList { get; set; }

        /// <summary>
        /// If specified, indicates that the email should be signed using S/MIME.
        /// </summary>
        [Parameter(
           Mandatory = false,
           HelpMessage = "Use this switch to indicate that you want to sign your email using S/MIME."
        )]
        public SwitchParameter SignMail { get; set; }

        /// < summary >
        /// An X509Certificate2 object representing the S/MIME certificate used to sign or encrypt mail.
        /// </ summary >
        [Parameter(
           Mandatory = false,
           HelpMessage = "Provide an X509Certificate2 object representing your S/MIME certificate used for signing or encrypting emails."
        )]
        [Alias("X509MailCertificate", "SMimeCert")]
        public X509Certificate2 SMimeCertificate { get; set; }

        /// < summary >
        /// Specifies which digest algorithm should be used when signing an S/MIME message.
        /// Defaults to Sha256 if not specified.
        /// </ summary >
        [Parameter(
           Mandatory = false,
           HelpMessage = "Specify which digest algorithm to use when signing S/MIME messages. Default is Sha256 if not provided."
        )]
        public DigestAlgorithm SigningAlgorithm { get; set; } = DigestAlgorithm.Sha256;

        /// < summary >
        /// If specified, disables certificate revocation checking during SSL/TLS handshake.
        /// < / summary >
        [Parameter(
           Mandatory = false,
           HelpMessage = "Use this switch to disable certificate revocation checking during SSL/TLS handshake."
        )]
        public SwitchParameter DisableCertificateRevocation { get; set; }

        /// < summary >
        /// If specified, allows custom handling of server certificate validation during SSL/TLS handshake.
        /// < / summary >
        [Parameter(
            Mandatory = false,
            HelpMessage = "Use this switch for custom handling of server certificate validation during SSL/TLS handshake."
        )]
        public SwitchParameter ServerCertificateValidationCallback { get; set; }

        /// < summary >
        /// An array of X509Certificate2 objects representing client certificates used during SSL/TLS handshake.
        /// < / summary >
        [Parameter(
            Mandatory = false,
            HelpMessage = "Provide an array of X509Certificate2 objects representing client certificates used during SSL/TLS handshake."
        )]
        public X509Certificate2[] ClientCertificates { get; set; }

        [Parameter(
           Mandatory = false,
           HelpMessage = "When specified, simulates the operation without actually performing any actions."
        )]
        public SwitchParameter WhatIf { get; set; }

        #endregion

        #region private parameter

        /// <summary>
        /// Represents an SMTP client for sending emails.
        /// </summary>
        MailKit.Net.Smtp.SmtpClient SmtpClient;

        #endregion

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            MimeMessage Message = new MimeMessage();
            BodyBuilder Body = new BodyBuilder();
            SmtpClient = new MailKit.Net.Smtp.SmtpClient();

            try
            {
                //from
                MailboxAddress from = ParseMailboxAddress(From);
                Message.From.Add(from);

                //to
                InternetAddressList to = ParseToInternetAddressList(To);
                Message.To.AddRange(to);

                //cc
                if (CC != null && CC.Length > 0)
                {
                    InternetAddressList ccList = ParseToInternetAddressList(CC);
                    Message.Cc.AddRange(ccList);
                }

                //bcc
                if (BCC != null && BCC.Length > 0)
                {
                    InternetAddressList bccList = ParseToInternetAddressList(BCC);
                    Message.Bcc.AddRange(bccList);
                }

                // replyTo
                if (ReplyTo != null && ReplyTo.Length > 0)
                {
                    InternetAddressList replyTo = ParseToInternetAddressList(ReplyTo);
                    Message.ReplyTo.AddRange(replyTo);
                }

                //subject
                if (!string.IsNullOrWhiteSpace(Subject))
                {
                    Message.Subject = Subject;
                }

                //text body
                if (!string.IsNullOrWhiteSpace(TextBody))
                {
                    Body.TextBody = TextBody;
                }

                //html body
                if (!string.IsNullOrWhiteSpace(HTMLBody))
                {
                    Body.HtmlBody = HttpUtility.HtmlDecode(HTMLBody);
                }

                //attachment(s)
                if (AttachmentList?.Length > 0)
                {
                    foreach (string Attachment in AttachmentList)
                    {
                        Body.Attachments.Add(Attachment);
                    }
                }

                //add bodybuilder to body
                Message.Body = Body.ToMessageBody();

                //add digital signature
                if (SignMail.IsPresent)
                {
                    // Certificate required
                    if (SMimeCertificate == null)
                    {
                        throw new ArgumentException("The required signing certificate is not available. Please ensure that the certificate is properly configured.");
                    }

                    // Update to a more secure algorithm
                    if (IsAlgorithmOutdated(SigningAlgorithm))
                    {
                        SigningAlgorithm = DigestAlgorithm.Sha256;
                    }

                    // Create a CmsSigner with the certificate
                    var signer = new CmsSigner(SMimeCertificate)
                    {
                        DigestAlgorithm = SigningAlgorithm
                    };

                    // Sign the message
                    using (var ctx = new TemporarySecureMimeContext())
                    {
                        Message.Body = MultipartSigned.Create(ctx, signer, Message.Body);
                    }
                }

                // disable CheckCertificateRevocation
                if (DisableCertificateRevocation.IsPresent)
                {
                    SmtpClient.CheckCertificateRevocation = false;
                }

                //accept all certificates regardless of errors (not recommended in production)
                if (ServerCertificateValidationCallback.IsPresent)
                {
                    SmtpClient.ServerCertificateValidationCallback = (s, c, h, e) => true;
                }

                //add certificates if needed
                if (ClientCertificates != null && ClientCertificates.Length > 0)
                {
                    foreach (var cert in ClientCertificates)
                    {
                        if (!cert.HasPrivateKey)
                        {
                            throw new InvalidOperationException($"Certificate with thumbprint {cert.Thumbprint} does not have a private key.");
                        }

                        SmtpClient.ClientCertificates.Add(cert);
                    }
                }

                if (WhatIf.IsPresent)
                {
                    Console.WriteLine($"WhatIf: Performing the operation \"Send Email\" on target SMTP server \"{SMTPServer}\" with the following details:\n" +
                      $"- Subject: {Subject}\n" +
                      $"- From: {From}\n" +
                      $"- Recipients: {string.Join(", ", To)}\n" +
                      $"- CC: {string.Join(", ", CC ?? Array.Empty<string>())}\n" +
                      $"- BCC: {string.Join(", ", BCC ?? Array.Empty<string>())}\n" +
                      $"- Attachments: {string.Join(", ", AttachmentList ?? Array.Empty<string>())}\n" +
                      $"- SMTP Server: {SMTPServer}:{Port}");
                }
                else
                {
                    try
                    {
                        // Connect to SMTP server
                        SmtpClient.Connect(SMTPServer, Port, UseSSL.IsPresent
                            ? MailKit.Security.SecureSocketOptions.Auto
                            : MailKit.Security.SecureSocketOptions.None);
                    }
                    catch (SmtpProtocolException smtpEx)
                    {
                        throw new InvalidOperationException("Failed to connect to the SMTP server. Please check the server address and port number.", smtpEx);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidOperationException("An unexpected error occurred while trying to connect to the SMTP server. Please verify your configuration.", ex);
                    }

                    try
                    {
                        if (Credential != null)
                        {
                            IntPtr bstr = IntPtr.Zero;
                            try
                            {
                                bstr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(Credential.Password);
                                SmtpClient.Authenticate(Credential.UserName, System.Runtime.InteropServices.Marshal.PtrToStringAuto(bstr));
                            }
                            finally
                            {
                                if (bstr != IntPtr.Zero)
                                    System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(bstr);
                            }
                        }
                    }
                    catch (AuthenticationException authEx)
                    {
                        throw new InvalidOperationException("Authentication failed. Please check your username and password.", authEx);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidOperationException("An unexpected error occurred during authentication. Please ensure that all parameters are correctly set.", ex);
                    }

                    SmtpClient.Send(Message);
                }
            }
            finally
            {
                if (SmtpClient.IsConnected)
                {
                    SmtpClient.Disconnect(true);
                }
                SmtpClient.Dispose();
                SmtpClient = null;
            }
        }
        protected override void EndProcessing()
        {
            base.EndProcessing();

            if (SmtpClient?.IsConnected == true)
            {
                SmtpClient.Disconnect(true);
            }
        }

        /// <summary>
        /// Determines whether the specified digest algorithm is considered outdated or insecure.
        /// </summary>
        /// <param name="algorithm">The digest algorithm to check.</param>
        /// <returns>
        ///   <c>true</c> if the specified algorithm is outdated or insecure; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsAlgorithmOutdated(DigestAlgorithm algorithm)
        {
            return algorithm == DigestAlgorithm.None ||
                   algorithm == DigestAlgorithm.MD2 ||
                   algorithm == DigestAlgorithm.MD4 ||
                   algorithm == DigestAlgorithm.MD5 ||
                   algorithm == DigestAlgorithm.Sha1 || // SHA-1 is considered weak
                   algorithm == DigestAlgorithm.RipeMD160; // RIPEMD-160 is also considered less secure
        }

        /// <summary>
        /// Converts a string into a MailboxAddress.
        /// Validates the email format and throws a FormatException if the address is invalid.
        /// </summary>
        /// <param name="address">The input string to convert to a MailboxAddress.</param>
        /// <returns>A MailboxAddress parsed from the input string.</returns>
        /// <exception cref="FormatException">Thrown when the email address format is invalid. 
        /// The exception message provides guidance on the correct format.</exception>
        /// <exception cref="Exception">Thrown for any other errors encountered during parsing.</exception>
        private static MailboxAddress ParseMailboxAddress(string address)
        {
            try
            {
                return MailboxAddress.Parse(address);
            }
            catch (FormatException ex)
            {
                throw new FormatException($"Invalid email format for '{address}'. Ensure the email address is in the format 'example@domain.com'.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while converting the input to a MailboxAddress. Please verify the input and try again.", ex);
            }
        }

        /// <summary>
        /// Converts a string array of email addresses into an InternetAddressList.
        /// Validates each address format and throws a FormatException if any address is invalid.
        /// </summary>
        /// <param name="addressList">An array of email addresses to convert to an InternetAddressList.</param>
        /// <returns>An InternetAddressList containing all valid, parsed email addresses.</returns>
        /// <exception cref="FormatException">Thrown when one or more email addresses are in an invalid format. 
        /// The exception message specifies the problematic address and provides guidance on the correct format.</exception>
        /// <exception cref="Exception">Thrown for any other errors encountered during the conversion process.</exception>
        private static InternetAddressList ParseToInternetAddressList(string[] addressList)
        {
            InternetAddressList internetAddressList = new InternetAddressList();
            try
            {
                foreach (var str in addressList)
                {
                    if (string.IsNullOrWhiteSpace(str))
                        continue;

                    internetAddressList.Add(InternetAddress.Parse(str));
                }
            }
            catch (FormatException ex)
            {
                // Capture and report the problematic email address and provide an example of correct formatting.
                throw new FormatException($"Invalid email format encountered in the provided address list: '{ex.Message}'. " +
                                          $"Ensure all email addresses are in a valid format, such as 'example@domain.com'.", ex);
            }
            catch (Exception ex)
            {
                // For any other unforeseen errors, rethrow with additional context.
                throw new Exception("An error occurred while converting to InternetAddressList. Please review the input email addresses.", ex);
            }


            return internetAddressList;
        }
    }
}
