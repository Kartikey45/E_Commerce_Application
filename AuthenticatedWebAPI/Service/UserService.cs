using System.Security.Claims;
using AuthenticatedWebAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace AuthenticatedWebAPI.Service
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContext;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public UserService(IHttpContextAccessor httpContext, UserManager<User> userManager, 
            RoleManager<IdentityRole> roleManager, IEmailService emailService)
        {
            _httpContext = httpContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        public string GetUserId()
        {
            return _httpContext.HttpContext.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        }

        public bool IsAuthenticated() 
        {
            return _httpContext.HttpContext.User.Identity.IsAuthenticated;
        }

        public async Task<UserCreationResultDto> AddUserAsync(SignUpUserDto signUpUser)
        {
            var result = new UserCreationResultDto();

            try
            {
                // Check if duplicate user exists
                var userExists = await _userManager.FindByEmailAsync(signUpUser.Email);
                if (userExists != null)
                {
                    result.Success = false;
                    result.Message = $"Email '{signUpUser.Email}' already exists.";
                    return result;
                }

                // Check if the role exists
                var roleExists = await _roleManager.RoleExistsAsync(signUpUser.RoleName);
                if (!roleExists)
                {
                    result.Success = false;
                    result.Message = $"Role '{signUpUser.RoleName}' does not exist.";
                    return result;
                }

                var user = new User()
                {
                    Name = signUpUser.Name,
                    Email = signUpUser.Email,
                    UserName = signUpUser.Email,
                    IsAdmin = signUpUser.IsAdmin
                };

                var identityResult = await _userManager.CreateAsync(user, signUpUser.Password);
                if (!identityResult.Succeeded)
                {
                    result.Success = false;
                    result.Message = "User creation failed.";
                    result.IdentityResult = identityResult;
                    result.Errors = identityResult.Errors.Select(e => e.Description).ToList();
                    return result;
                }

                // Add user to the role
                var roleAssignmentResult = await _userManager.AddToRoleAsync(user, signUpUser.RoleName);
                if (!roleAssignmentResult.Succeeded)
                {
                    result.Success = false;
                    result.Message = "Role assignment failed.";
                    result.IdentityResult = roleAssignmentResult;
                    result.Errors = roleAssignmentResult.Errors.Select(e => e.Description).ToList();
                    return result;
                }

                // Send email confirmation
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                if (!string.IsNullOrEmpty(token))
                {
                    await _emailService.SendEmailForConfirmation(user, token);
                }

                result.Success = true;
                result.Message = "User registered successfully.";
                result.IdentityResult = identityResult;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = "Something went wrong, please try again. " + ex.Message;
                result.Errors.Add(ex.Message);
            }

            return result;
        }
    }
}
