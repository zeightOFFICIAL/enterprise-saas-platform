using Microsoft.AspNetCore.Identity;

namespace saas_platform.backend.Entities
{
    public class User : IdentityUser<Guid>
    {
        // Do not store plaintext password or duplicate EmailConfirmed.
        // Use IdentityUser's built-in PasswordHash and EmailConfirmed.

    }
}