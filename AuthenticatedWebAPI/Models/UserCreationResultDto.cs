using Microsoft.AspNetCore.Identity;

namespace AuthenticatedWebAPI.Models
{
    public class UserCreationResultDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public IdentityResult? IdentityResult { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}
