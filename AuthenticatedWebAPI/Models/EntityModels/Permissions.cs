using System.ComponentModel.DataAnnotations;

namespace AuthenticatedWebAPI.Models.EntityModels
{
    public class Permissions
    {
        [Key]
        [StringLength(500)]
        public string Id { get; set; }

        [Required]
        [StringLength(200)]
        public string Name { get; set; }

        [StringLength(500)]
        public string? Description { get; set; }

    }
}
