using AuthenticatedWebAPI.Models.Role;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticatedWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
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

            if (result.Succeeded)
            {
                return Created();
            }
            return BadRequest(result.Errors);
        }

        [HttpGet]
        public IActionResult GetAllRoles()
        {
            var roles =  _roleManager.Roles.ToList();
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
            if (role.Id != existingRole?.Id)
            {
                return BadRequest($"Role '{roleDto.Name}' already exists, it must be unique.");
            }

            role.Name = roleDto.Name;
            var result = await _roleManager.UpdateAsync(role);

            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest(result.Errors);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null) return NotFound();

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest(result.Errors);
        }
    }
}
