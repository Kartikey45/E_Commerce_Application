using Microsoft.EntityFrameworkCore;

namespace AuthenticatedWebAPI.Models.EntityModels
{
    [PrimaryKey(nameof(RoleId), nameof(PermissionId))]
    public class RolePermissions
    {
        public string RoleId { get; set; }

        public string PermissionId { get; set; }

    }
}
