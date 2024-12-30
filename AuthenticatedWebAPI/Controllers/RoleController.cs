using AuthenticatedWebAPI.Data;
using AuthenticatedWebAPI.Models.EntityModels;
using AuthenticatedWebAPI.Models.Role;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthenticatedWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _dbContext;

        public RoleController(RoleManager<IdentityRole> roleManager, ApplicationDbContext dbContext)
        {
            _roleManager = roleManager;
            _dbContext = dbContext;
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] RoleDto roleDto)
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

            // Check if role already exists
            var roleExists = await _roleManager.RoleExistsAsync(roleDto.Name);
            if (roleExists)
            {
                return BadRequest($"Role '{roleDto.Name}' already exists, it must be unique.");
            }

            var role = new IdentityRole { Name = roleDto.Name };
            var result = await _roleManager.CreateAsync(role);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            if (roleDto.Permissions == null || roleDto.Permissions.Count == 0)
            {
                return Created();
            }

            bool allPermissionsExist = roleDto.Permissions.All(p => _dbContext.Permissions.Any(dbP => dbP.Id == p));
            if (!allPermissionsExist)
            {
                // Not all required permissions exist
                return BadRequest($"Some Permissions does not exists.");
            }

            // Add Roles
            var rolePermissions = roleDto.Permissions.Select(p => new RolePermissions { RoleId = role.Id, PermissionId = p }).ToList();
            await _dbContext.RolePermissions.AddRangeAsync(rolePermissions);
            await _dbContext.SaveChangesAsync();
            return Created();

        }

        [HttpGet]
        public IActionResult GetAllRoles()
        {
            var roles = _roleManager.Roles.ToList();
            if (roles == null || roles.Count <= 0)
            {
                return NotFound();
            }
            return Ok(roles);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            return Ok(role);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateRole(string id, [FromBody] RoleDto roleDto)
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

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            // Check duplicate role
            var existingRole = await _roleManager.FindByNameAsync(roleDto.Name);
            if (existingRole != null && role.Id != existingRole.Id)
            {
                return BadRequest($"Role '{roleDto.Name}' already exists, it must be unique.");
            }

            role.Name = roleDto.Name;
            var result = await _roleManager.UpdateAsync(role);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            // Update RolePermissions

            // 1. Get existing permissions for the role
            var existingRolePermissions = await _dbContext.RolePermissions
                .Where(rp => rp.RoleId == role.Id)
                .ToListAsync();

            // 2. Identify permissions to be removed (existing but not in DTO)
            var permissionsToRemove = existingRolePermissions.Where(rp => !roleDto.Permissions.Contains(rp.PermissionId)).ToList();

            // 3. Identify permissions to be added (new in DTO but not existing)
            var permissionsToAdd = roleDto.Permissions.Except(existingRolePermissions.Select(rp => rp.PermissionId)).ToList();

            // 4. Remove permissions
            _dbContext.RolePermissions.RemoveRange(permissionsToRemove);

            // 5. Create new RolePermissions for permissions to be added
            var newRolePermissions = permissionsToAdd.Select(p => new RolePermissions { RoleId = role.Id, PermissionId = p });

            // 6. Add new RolePermissions
            await _dbContext.RolePermissions.AddRangeAsync(newRolePermissions);

            // 7. Save changes to the database
            await _dbContext.SaveChangesAsync();

            return Ok();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) 
                return NotFound();

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest(result.Errors);
        }
    }
}
