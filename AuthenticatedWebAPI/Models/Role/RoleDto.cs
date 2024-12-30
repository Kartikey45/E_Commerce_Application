using System.ComponentModel.DataAnnotations;

namespace AuthenticatedWebAPI.Models.Role
{
    public class RoleDto
    {
        [Required(ErrorMessage = "role required")]
        [Display(Name = "Role Name")]
        public string Name { get; set; }

        [Display(Name = "Permissions")]
        public List<string> Permissions { get; set; } = new();
    }
}
