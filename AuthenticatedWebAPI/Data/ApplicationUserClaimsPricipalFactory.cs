using AuthenticatedWebAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace AuthenticatedWebAPI.Data
{
    public class ApplicationUserClaimsPricipalFactory : UserClaimsPrincipalFactory<User, IdentityRole>
    {
        public ApplicationUserClaimsPricipalFactory(UserManager<User> userManager, 
            RoleManager<IdentityRole> roleManager, IOptions<IdentityOptions> options) : base(userManager, roleManager, options)
        {
                
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(User user)
        {
            var identity = await base.GenerateClaimsAsync(user);
            identity.AddClaim(new Claim("Name", user.Name));
            identity.AddClaim(new Claim("IsAdmin", user.IsAdmin.ToString()));
            return identity;
        }

    }
}
