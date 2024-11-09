using MimeKit;
using System;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Web;
using System.Security.Cryptography.X509Certificates;

namespace Send_MailKitMessage
{
    public class ModuleInitializer : IModuleAssemblyInitializer
    {
        public void OnImport()
        {
            //for some reason running Send-MailKitMessage in Windows PowerShell ALWAYS returned the following exception: "Could not load file or assembly 'System.Buffers, Version=4.0.2.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51' or one of its dependencies. The system cannot find the file specified."
            //and I COULD NOT nail down what was causing it
            //so per https://devblogs.microsoft.com/powershell/resolving-powershell-module-assembly-dependency-conflicts/ I am using an AssemblyResolve event handler to create a dynamic binding redirect so all calls to System.Buffers use the same assembly
            AppDomain.CurrentDomain.AssemblyResolve += DependencyResolution.ResolveSystemBuffers;
        }
    }

    internal static class DependencyResolution
    {
        private static readonly string CurrentLocation = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        public static Assembly ResolveSystemBuffers(object sender, ResolveEventArgs args)
        {
            //parse the assembly name
            var assemblyName = new AssemblyName(args.Name);

            //only handle the dependency we care about
            if (!assemblyName.Name.Equals("System.Buffers"))
            {
                return null;
            }

            return Assembly.LoadFrom(Path.Combine(CurrentLocation, "System.Buffers.dll"));
        }
    }

    [Cmdlet(VerbsCommunications.Send, "MailKitMessage")]    //I think the [CmdletBinding] piece is applicable to true PowerShell functions, not compiled cmdlets https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_cmdletbindingattribute?view=powershell-7.1#long-description
    [OutputType(typeof(void))]
    public class Send_MailKitMessage : PSCmdlet
    {
        [Parameter(
            Mandatory = false)]
        public SwitchParameter UseSecureConnectionIfAvailable { get; set; } = SwitchParameter.Present;  //default to present if no value is passed

        [Parameter(
            Mandatory = false)]
        public PSCredential Credential { get; set; }

        [Parameter(
            Mandatory = true)]
        public string SMTPServer { get; set; }

        [Parameter(
            Mandatory = true)]
        public int Port { get; set; }

        [Parameter(
            Mandatory = true)]
        public string From { get; set; }

        [Parameter(
            Mandatory = true)]
        public string[] RecipientList { get; set; }

        [Parameter(
            Mandatory = false)]
        public string[] CCList { get; set; }

        [Parameter(
            Mandatory = false)]
        public string[] BCCList { get; set; }

        [Parameter(
            Mandatory = false)]
        public string Subject { get; set; }

        [Parameter(
            Mandatory = false)]
        public string TextBody { get; set; }

        [Parameter(
            Mandatory = false)]
        public string HTMLBody { get; set; }

        [Parameter(
            Mandatory = false)]
        public string[] AttachmentList { get; set; }

        [Parameter(
            Mandatory = false,
            HelpMessage = "Disables certificate revocation checks. This can be useful when occasional downtimes, network issues, or offline certificate authorities prevent checking the revocation status of certificates. " +
                  "Be aware that disabling revocation checks may pose security risks."
        )]
        public SwitchParameter DisableCertificateRevocation { get; set; }

        [Parameter(
            Mandatory = false,
            HelpMessage = "Bypass server certificate validation entirely, accepting all certificates regardless of errors. " +
                  "This is not recommended for production environments, as it exposes the system to potential security risks. " +
                  "However, it can be useful for debugging scenarios or when working with self-signed certificates."
        )]
        public SwitchParameter ServerCertificateValidationCallback { get; set; }

        [Parameter(
            Mandatory = false)]
        public X509Certificate2[] ClientCertificates { get; set; }

        [Parameter(
           Mandatory = false,
           HelpMessage = "When specified, simulates the operation without actually performing any actions."
        )]
        public SwitchParameter WhatIf { get; set; }

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {

            MimeMessage Message = new MimeMessage();
            BodyBuilder Body = new BodyBuilder();
            MailKit.Net.Smtp.SmtpClient Client = new MailKit.Net.Smtp.SmtpClient();

            try
            {

                //from
                MailboxAddress from = ParseMailboxAddress(From);
                Message.From.Add(from);

                //to
                InternetAddressList recipientList = ParseToInternetAddressList(RecipientList);
                Message.To.AddRange(recipientList);

                //cc
                if (CCList != null && CCList.Length > 0)
                {
                    InternetAddressList ccList = ParseToInternetAddressList(CCList);
                    Message.Cc.AddRange(ccList);
                }

                //bcc
                if (BCCList != null && BCCList.Length > 0)
                {
                    InternetAddressList bcList = ParseToInternetAddressList(BCCList);
                    Message.Bcc.AddRange(bcList);
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
                    Body.HtmlBody = HttpUtility.HtmlDecode(HTMLBody);    //decode html in case it was encoded along the way
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

                // Disables certificate revocation checks
                if (DisableCertificateRevocation.IsPresent)
                {
                    Client.CheckCertificateRevocation = false;
                }

                // Bypass server certificate validation
                if (ServerCertificateValidationCallback.IsPresent)
                {
                    Client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                }

                // To authenticate the client to the server using a certificate
                if (ClientCertificates != null && ClientCertificates.Length > 0)
                {
                    foreach (var cert in ClientCertificates)
                    {
                        if (!cert.HasPrivateKey)
                        {
                            throw new InvalidOperationException($"Certificate with thumbprint {cert.Thumbprint} does not have a private key.");
                        }

                        Client.ClientCertificates.Add(cert);
                    }
                }

                if (!WhatIf.IsPresent)
                {
                    // smtp Connect
                    Client.Connect(SMTPServer, Port, (UseSecureConnectionIfAvailable.IsPresent 
                        ? MailKit.Security.SecureSocketOptions.Auto 
                        : MailKit.Security.SecureSocketOptions.None));

                    // use smtp Authentication
                    if (Credential != null)
                    {
                        Client.Authenticate(Credential.UserName, (System.Runtime.InteropServices.Marshal.PtrToStringAuto(System.Runtime.InteropServices.Marshal.SecureStringToBSTR(Credential.Password))));
                    }

                    // smtp send message
                    Client.Send(Message);
                } else
                {
                    Console.WriteLine($"WhatIf: Performing the operation \"Send Email\" on target SMTP server \"{SMTPServer}\" with the following details:\n" +
                      $"- Subject: {Subject}\n" +
                      $"- From: {From}\n" +
                      $"- Recipients: {string.Join(", ", RecipientList)}\n" +
                      $"- CC: {string.Join(", ", CCList ?? Array.Empty<string>())}\n" +
                      $"- BCC: {string.Join(", ", BCCList ?? Array.Empty<string>())}\n" +
                      $"- Attachments: {string.Join(", ", AttachmentList ?? Array.Empty<string>())}\n" +
                      $"- SMTP Server: {SMTPServer}:{Port}");
                }

            }
            catch (Exception e)
            {
                
                throw e;
            }
            finally
            {
                if (Client.IsConnected)
                {
                    Client.Disconnect(true);
                }
            }
        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            
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

    public class ModuleCleanup : IModuleAssemblyCleanup
    {
        public void OnRemove(PSModuleInfo psModuleInfo)
        {
            AppDomain.CurrentDomain.AssemblyResolve -= DependencyResolution.ResolveSystemBuffers;
        }
    }
}
