using AuthenticatedWebAPI.Models;

namespace AuthenticatedWebAPI.Service
{
    public interface IEmailService
    {
        Task SendTestEmail(UserEmailOptions userEmailOptions);
        Task SendEmailForConfirmation(User user, string token);
        Task SendForgetPasswordEmail(User user, string token);
    }
}