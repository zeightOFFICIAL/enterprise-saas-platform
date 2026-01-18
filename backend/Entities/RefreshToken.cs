using System.ComponentModel.DataAnnotations;

namespace saas_platform.backend.Entities
{
    public class RefreshToken
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        public Guid UserId { get; set; }

        [Required]
        public string Token { get; set; } = string.Empty;

        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; } = false;

        public DateTime Created { get; set; } = DateTime.UtcNow;
        public string CreatedByIp { get; set; } = string.Empty;

        public DateTime? Revoked { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }
    }
}