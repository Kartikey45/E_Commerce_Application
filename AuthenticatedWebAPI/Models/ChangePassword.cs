using System.ComponentModel.DataAnnotations;

namespace AuthenticatedWebAPI.Models
{
    public class ChangePassword
    {
        [Required, DataType(DataType.Password), Display(Name = "Current Passowrd")]
        public string CurrentPassword { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "New Passowrd")]
        public string NewPassword { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "Confirm New Passowrd")]
        [Compare("NewPassword", ErrorMessage = "Confirm new password does not match")]
        public string ConfirmNewPassword { get; set; }
    }
}
