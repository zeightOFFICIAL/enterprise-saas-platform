using Microsoft.AspNetCore.Identity;

namespace saas_platform.Backend.Entities
{
    public class User : IdentityUser<Guid>
    {
        public string Email { get; set; }
        public string Password { get; set; } = "Password";
    }
}