using System.ComponentModel.DataAnnotations;

namespace AuthenticatedWebAPI.Models
{
    public class SignUpUser
    {
        [Required(ErrorMessage = "please enter your name")]
        [Display(Name = "Name")]
        public string Name { get; set; }

        [Required(ErrorMessage = "please enter your email")]
        [Display(Name = "Email address")]
        [EmailAddress(ErrorMessage = "Please enter a valid email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "please enter a strong password")]
        [Compare("ConfirmPassword", ErrorMessage = "Password does not match")]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Required(ErrorMessage = "please enter your password")]
        [Display(Name = "ConfirmPassword")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "Is admin")]
        public bool IsAdmin { get; set; } = false;
    }
}
