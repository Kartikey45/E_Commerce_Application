using System.Security.Claims;
using AuthenticatedWebAPI.Models;
using AuthenticatedWebAPI.Data;
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
        private readonly SignInManager<User> _signInManager;
        private readonly ITokenService _tokenService;
        private readonly ApplicationDbContext _dbContext;

        public UserService(IHttpContextAccessor httpContext, UserManager<User> userManager, 
            RoleManager<IdentityRole> roleManager, IEmailService emailService,
            SignInManager<User> signInManager, ITokenService tokenService, ApplicationDbContext dbContext)
        {
            _httpContext = httpContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _dbContext = dbContext;
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

        public async Task<AuthenticationResultDto> AuthenticateUserAsync(SignInUserDto loginDto)
        {
            var result = new AuthenticationResultDto();

            try
            {
                var user = await _userManager.FindByEmailAsync(loginDto.Email);
                if (user == null)
                {
                    result.Success = false;
                    result.Message = "check your login credentials and try again.";
                    return result;
                }

                var signInResult = await _signInManager.PasswordSignInAsync(user, loginDto.Password, loginDto.RememberMe, true).ConfigureAwait(false);
                
                if (signInResult.IsLockedOut)
                {
                    result.Success = false;
                    result.Message = "Account has been blocked , please try after sometime.";
                    return result;
                }
                
                if (signInResult.IsNotAllowed)
                {
                    result.Success = false;
                    result.Message = "Not allowed to login.";
                    return result;
                }
                
                if (!signInResult.Succeeded)
                {
                    result.Success = false;
                    result.Message = "check your login credentials and try again.";
                    return result;
                }

                var roles = await _userManager.GetRolesAsync(user);

                // Fetch permissions
                var roleIds = _roleManager.Roles.Where(r => roles.Contains(r.Name)).Select(r => r.Id).ToList();
                var permissionsIds = _dbContext.RolePermissions
                    .Where(rp => roleIds.Contains(rp.RoleId))
                    .Select(rp => rp.PermissionId)
                    .Distinct()
                    .ToList();

                var permissionNames = _dbContext.Permissions
                    .Where(p => permissionsIds.Contains(p.Id))
                    .Select(p => p.Name)
                    .ToList();

                var token = _tokenService.GenerateToken(user, roles, permissionNames);

                result.Success = true;
                result.Message = "Authentication successful";
                result.Token = token;
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
