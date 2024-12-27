namespace AuthenticatedWebAPI.Models
{
    public class ForgotPasswordModelDto
    {
        public string Email { get; set; }
        public bool EmailSent { get; set; }
    }
}