using AuthenticatedWebAPI.Data;
using AuthenticatedWebAPI.Models;
using AuthenticatedWebAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthenticatedWebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IUserService _userService;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        private readonly ApplicationDbContext _dbContext;


        public UserController(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<IdentityRole> roleManager,
            IUserService userService, IEmailService emailService, ITokenService tokenService, ApplicationDbContext dbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _userService = userService;
            _emailService = emailService;
            _tokenService = tokenService;
            _roleManager = roleManager;
            _dbContext = dbContext;
        }


        #region User Management

        [HttpGet("logout"), Authorize(Roles = "Admin")]
        public async Task<ActionResult> LogoutUser()
        {
            string message = "You are free to go !";
            try
            {
                await _signInManager.SignOutAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return BadRequest("something went wrong, please try again." + ex.Message);
            }

            return Ok(new { message = message });
        }

        [HttpGet("admin"), Authorize(Roles = "Admin")]
        public ActionResult AdminPage()
        {
            string[] partners =
            {
                "Raja", "Bill Gates", "Elon Mask", "Taylor Swift", "Jeff Bezos", "Mark Zukerberg", "Joe Bidden", "Putin"
            };
            return Ok(new { trustedPartners = partners });
        }

        [HttpGet("home/{email}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult> HomePage(string email)
        {
            var _userInfo = await _userManager.FindByEmailAsync(email).ConfigureAwait(false);
            if (_userInfo == null)
            {
                return BadRequest(new { message = "something went wrong, please try again." });
            }
            return Ok(new { userInfo = _userInfo });
        }

        [HttpGet("check-authentication"), Authorize(Roles = "Admin")]
        public async Task<ActionResult> CheckUser()
        {
            string message = "logged in";
            User currentUser = new User();
            try
            {
                var _user = HttpContext.User;
                var principals = new ClaimsPrincipal(_user);
                //var result = _signInManager.IsSignedIn(principals);
                var result = _userService.IsAuthenticated();
                if (result)
                {
                    currentUser = await _signInManager.UserManager.GetUserAsync(principals).ConfigureAwait(false);
                }
                else
                {
                    return Forbid("access denied");
                }
            }
            catch (Exception ex)
            {
                return BadRequest("something went wrong , please try again" + ex.Message);
            }

            return Ok(new { message = message, user = currentUser });
        }

        [HttpPost("change-password"), Authorize(Roles = "Admin")]
        public async Task<ActionResult> ChangePassword(ChangePasswordDto model)
        {
            IdentityResult result = null;
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "invalid parameters details" });
                }
                var userId = _userService.GetUserId();
                var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
                if (user != null)
                {
                    result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword).ConfigureAwait(false);
                }
                else
                {
                    return NotFound("not found");
                }
            }
            catch (Exception ex)
            {
                return BadRequest("something went wrong, please try again." + ex.Message);
            }

            return Ok(new { message = "password changed successfully", result = result });
        }

        [HttpGet("confirm-email")]
        public async Task<ActionResult> ConfirmEmail(string uid, string token)
        {
            if (!string.IsNullOrEmpty(uid) && !string.IsNullOrEmpty(token))
            {
                token = token.Replace(' ', '+');
                var user = await _userManager.FindByIdAsync(uid);
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (!result.Succeeded)
                {
                    return Conflict("Email not confirmed.");
                }
                return Ok("Email confirmed !");
            }
            return BadRequest("invalid parameters passed");
        }

        [HttpPost("resend-email-confirmation-mail")]
        public async Task<ActionResult> ConfirmEmail(EmailConfirmModelDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Conflict("Something went wrong !");
            }
            if (user.EmailConfirmed)
            {
                model.IsConfirmed = true;
                return Ok("Email id is already confirmed !");
            }
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(token))
            {
                await _emailService.SendEmailForConfirmation(user, token);
                model.EmailSent = true;
            }
            return Ok("Email Sent !");
        }

        [AllowAnonymous, HttpPost("forgot-password")]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordModelDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Conflict("Something went wrong !");
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(token))
            {
                await _emailService.SendForgetPasswordEmail(user, token);
                model.EmailSent = true;
            }
            return Ok("Email Sent !");
        }

        [AllowAnonymous, HttpPost("reset-password")]
        public async Task<ActionResult> ResetPassword(ResetPasswordModelDto model)
        {
            model.Token = model.Token.Replace(' ', '+');
            var user = await _userManager.FindByIdAsync(model.UserId);
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (!result.Succeeded)
            {
                return Conflict("unable to reset password !");
            }
            model.IsSuccess = true;
            return Ok("Password successfullly reset !");
        }

        #endregion

        #region Authenticate

        [HttpPost("add-user")]
        public async Task<ActionResult> AddUser([FromBody] SignUpUserDto signUpUser)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState
                   .Where(x => x.Value.Errors.Any())
                   .ToDictionary(
                       x => x.Key,
                       x => x.Value.Errors.Select(e => e.ErrorMessage).ToList()
                   );
                return BadRequest(errors);
            }

            var result = await _userService.AddUserAsync(signUpUser);

            if (!result.Success)
            {
                if (result.Errors.Any())
                {
                    return BadRequest(result.Errors);
                }
                return BadRequest(result.Message);
            }

            return Ok(new { message = result.Message, result = result.IdentityResult });
        }


        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] SignInUserDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState
                   .Where(x => x.Value.Errors.Any())
                   .ToDictionary(
                       x => x.Key,
                       x => x.Value.Errors.Select(e => e.ErrorMessage).ToList()
                   );
                return BadRequest(errors);
            }

            var result = await _userService.AuthenticateUserAsync(loginDto);

            if (!result.Success)
            {
                if (result.Errors.Any())
                {
                    return BadRequest(result.Errors);
                }
                return Unauthorized(result.Message);
            }

            return Ok(new { message = result.Message, token = result.Token });
        }

        #endregion

    }
}
