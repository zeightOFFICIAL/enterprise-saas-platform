using System.ComponentModel.DataAnnotations;

namespace saas_platform.backend.Entities
{
    public enum SubscriptionPlan
    {
        Free = 0,
        Pro = 1,
        Enterprise = 2
    }

    public class Subscription
    {
        [Key]
        public Guid Id { get; set; }

        public Guid TenantId { get; set; }

        public SubscriptionPlan Plan { get; set; }

        public string Status { get; set; }

        public string? StripeCustomerId { get; set; }

        public string? StripeSubscriptionId { get; set; }

        public DateTime? CurrentPeriodEnd { get; set; }

        [Required]
        public DateTime CreatedAt { get; set; }
    }
}