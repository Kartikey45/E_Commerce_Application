using System.Collections.Generic;

namespace AuthenticatedWebAPI.Models
{
    public class AuthenticationResultDto
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Token { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}
