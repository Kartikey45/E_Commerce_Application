using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

public class DynamicPermissionAttribute : Attribute, IAuthorizationFilter
{
    private readonly string _requiredPermission;

    public DynamicPermissionAttribute(string requiredPermission)
    {
        _requiredPermission = requiredPermission;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        Console.WriteLine("OnAuthorization invoked.");

        // Check if user is authenticated
        if (!context.HttpContext.User.Identity?.IsAuthenticated ?? false)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        // Get the Permission claims from the token
        var permissions = context.HttpContext.User.Claims
            .Where(c => c.Type == "Permission")
            .Select(c => c.Value)
            .ToList();

        // Check if the required permission exists in the claims
        if (!permissions.Contains(_requiredPermission))
        {
            context.Result = new ForbidResult();
            return;
        }
    }
}

