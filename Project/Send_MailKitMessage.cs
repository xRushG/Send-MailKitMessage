﻿using MimeKit;
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
        public MailboxAddress From { get; set; }

        [Parameter(
            Mandatory = true)]
        public InternetAddressList RecipientList { get; set; }

        [Parameter(
            Mandatory = false)]
        public InternetAddressList CCList { get; set; }

        [Parameter(
            Mandatory = false)]
        public InternetAddressList BCCList { get; set; }

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
            Mandatory = false)]
        public SwitchParameter DisableCertificateRevocation { get; set; }

        [Parameter(
            Mandatory = false)]
        public SwitchParameter ServerCertificateValidationCallback { get; set; }

        [Parameter(
            Mandatory = false)]
        public X509Certificate2[] ClientCertificates { get; set; }

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
                Message.From.Add(From);

                //to
                Message.To.AddRange(RecipientList);

                //cc
                if (CCList?.Count > 0)
                {
                    Message.Cc.AddRange(CCList);
                }

                //bcc
                if (BCCList?.Count > 0)
                {
                    Message.Bcc.AddRange(BCCList);
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

                // disable CheckCertificateRevocation
                // Occasional downtimes, network issues, or offline servers can make it impossible to check the revocation status of certificates.
                if (DisableCertificateRevocation.IsPresent)
                {
                    Client.CheckCertificateRevocation = false;
                }

                // Accept all certificates regardless of errors (not recommended in production, good for debug.)
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

                // smtp Connect
                Client.Connect(SMTPServer, Port, (UseSecureConnectionIfAvailable.IsPresent ? MailKit.Security.SecureSocketOptions.Auto : MailKit.Security.SecureSocketOptions.None));

                // use smtp Authentication
                if (Credential != null)
                {
                    Client.Authenticate(Credential.UserName, (System.Runtime.InteropServices.Marshal.PtrToStringAuto(System.Runtime.InteropServices.Marshal.SecureStringToBSTR(Credential.Password))));
                }

                // smtp send message
                Client.Send(Message);

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
    }

    public class ModuleCleanup : IModuleAssemblyCleanup
    {
        public void OnRemove(PSModuleInfo psModuleInfo)
        {
            AppDomain.CurrentDomain.AssemblyResolve -= DependencyResolution.ResolveSystemBuffers;
        }
    }
}
