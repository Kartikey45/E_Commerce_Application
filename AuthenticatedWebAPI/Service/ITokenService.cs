using AuthenticatedWebAPI.Models;

namespace AuthenticatedWebAPI.Service
{
    public interface ITokenService
    {
        string GenerateToken(User user, IList<string> roles);
    }
}
