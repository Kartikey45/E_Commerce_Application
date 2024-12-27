namespace AuthenticatedWebAPI.Models
{
    public class EmailConfirmModelDto
    {
        public string Email { get; set; }
        public bool IsConfirmed { get; set; }
        public bool EmailSent { get; set; }
    }
}
