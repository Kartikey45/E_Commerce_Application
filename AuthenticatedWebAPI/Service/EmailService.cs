using AuthenticatedWebAPI.Models;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;
using System.Text;

namespace AuthenticatedWebAPI.Service
{
    public class EmailService : IEmailService
    {
        private const string templatePath = @"EmailTemplate/{0}.html";
        private readonly SMTPConfigModel _smtpConfigModel;
        private readonly IConfiguration _configuration;

        public EmailService(IOptions<SMTPConfigModel> smtpConfig, IConfiguration configuration)
        {
            _smtpConfigModel = smtpConfig.Value;
            _configuration = configuration;
        }

        public async Task SendTestEmail(UserEmailOptions userEmailOptions)
        {
            userEmailOptions.Subject = UpdatePlaceHolders("Hello {{UserName}}, This is test email subject from Web App", userEmailOptions.PlaceHolders);
            userEmailOptions.Body = UpdatePlaceHolders(GetEmailBody("TestEmail"), userEmailOptions.PlaceHolders);
            await SendEmail(userEmailOptions).ConfigureAwait(false);
        }

        public async Task SendEmailForConfirmation(User user, string token)
        {
            string appDomain = _configuration.GetSection("Application:AppDomain").Value;
            string confirmationLink = _configuration.GetSection("Application:EmailConfirmation").Value;
            UserEmailOptions options = new()
            {
                ToEmails = new List<string>() { user.Email },
                PlaceHolders = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("{{UserName}}", user.Name),
                    new KeyValuePair<string, string>("{{Link}}", string.Format(appDomain + confirmationLink, user.Id, token))
                }
            };
            await SendEmailForConfirmationEmail(options).ConfigureAwait(false);
        }

        private async Task SendEmailForConfirmationEmail(UserEmailOptions userEmailOptions)
        {
            userEmailOptions.Subject = UpdatePlaceHolders("Hello {{UserName}}, confirm your email id.", userEmailOptions.PlaceHolders);
            userEmailOptions.Body = UpdatePlaceHolders(GetEmailBody("EmailConfirm"), userEmailOptions.PlaceHolders);
            await SendEmail(userEmailOptions).ConfigureAwait(false);
        }

        public async Task SendForgetPasswordEmail(User user, string token)
        {
            string appDomain = _configuration.GetSection("Application:AppDomain").Value;
            string confirmationLink = _configuration.GetSection("Application:ForgotPassword").Value;
            UserEmailOptions options = new()
            {
                ToEmails = new List<string>() { user.Email },
                PlaceHolders = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("{{UserName}}", user.Name),
                    new KeyValuePair<string, string>("{{Link}}", string.Format(appDomain + confirmationLink, user.Id, token))
                }
            };
            await SendEmailForForgotPassword(options).ConfigureAwait(false);
        }

        private async Task SendEmailForForgotPassword(UserEmailOptions userEmailOptions)
        {
            userEmailOptions.Subject = UpdatePlaceHolders("Hello {{UserName}}, reset your password.", userEmailOptions.PlaceHolders);
            userEmailOptions.Body = UpdatePlaceHolders(GetEmailBody("ForgotPasssword"), userEmailOptions.PlaceHolders);
            await SendEmail(userEmailOptions).ConfigureAwait(false);
        }

        private async Task SendEmail(UserEmailOptions userEmailOptions)
        {
            MailMessage mail = new MailMessage()
            {
                Subject = userEmailOptions.Subject,
                Body = userEmailOptions.Body,
                From = new MailAddress(_smtpConfigModel.SenderAddress, _smtpConfigModel.SenderDisplayName),
                IsBodyHtml = _smtpConfigModel.IsBodyHtml
            };
            foreach (var toEmail in userEmailOptions.ToEmails)
            {
                mail.To.Add(toEmail);
            }

            var client = new SmtpClient(_smtpConfigModel.Host, _smtpConfigModel.Port)
            {
                Credentials = new NetworkCredential(_smtpConfigModel.UserName, _smtpConfigModel.Password),
                EnableSsl = true,
            };
            await client.SendMailAsync(mail);
        }

        private string GetEmailBody(string templateName)
        {
            var body = File.ReadAllText(string.Format(templatePath, templateName));
            return body;
        }

        private string UpdatePlaceHolders(string text, List<KeyValuePair<string, string>> keyvaluePairs)
        {
            if(!string.IsNullOrEmpty(text) && keyvaluePairs != null)
            {
                foreach (var placeholder in keyvaluePairs)
                {
                    if (text.Contains(placeholder.Key))
                    {
                        text = text.Replace(placeholder.Key, placeholder.Value);
                    }
                }
            }
            return text;
        }

        /*private async Task SendEmail(UserEmailOptions userEmailOptions)
        {
            MailMessage mail = new MailMessage()
            {
                Subject = userEmailOptions.Subject,
                Body = userEmailOptions.Body,
                From = new MailAddress(_smtpConfigModel.SenderAddress, _smtpConfigModel.SenderDisplayName),
                IsBodyHtml = _smtpConfigModel.IsBodyHtml
                
            };

            foreach (var toEmail in userEmailOptions.ToEmails)
            {
                mail.To.Add(toEmail);
            }
            NetworkCredential networkCredential = new NetworkCredential(_smtpConfigModel.UserName, _smtpConfigModel.Password);
            SmtpClient smtpClient = new SmtpClient()
            {
                Host = _smtpConfigModel.Host,
                Port = _smtpConfigModel.Port,
                EnableSsl = _smtpConfigModel.EnableSSL,
                UseDefaultCredentials = _smtpConfigModel.UseDefaultCredentials,
                Credentials = networkCredential
            };
            mail.BodyEncoding = Encoding.Default;
            await smtpClient.SendMailAsync(mail);
        }
*/


    }
}
