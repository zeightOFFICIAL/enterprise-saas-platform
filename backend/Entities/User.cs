using Microsoft.AspNetCore.Identity;

namespace saas_platform.Backend.Entities
{
    public class User : IdentityUser<Guid>
    {
        public string Password { get; set; } = "Password";
        public bool EmailConfirmed { get; set; } = false;
    }
}