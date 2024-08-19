namespace AuthenticatedWebAPI.Models
{
    public class ForgotPasswordModel
    {
        public string Email { get; set; }
        public bool EmailSent { get; set; }
    }
}