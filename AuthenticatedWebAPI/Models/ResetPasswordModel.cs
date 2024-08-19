namespace AuthenticatedWebAPI.Models
{
    public class ResetPasswordModel
    {
        public string UserId { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPasword { get; set; }
        public bool IsSuccess { get; set; }
    }
}
