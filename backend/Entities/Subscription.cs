using System.ComponentModel.DataAnnotations;

namespace saas_platform.Backend.Entities
{
    public class Subscription
    {
        [Key]
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string PlanType { get; set; }
        public string Status { get; set; }
    }
}