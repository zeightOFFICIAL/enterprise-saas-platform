using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using saas_platform.Backend.Data;
using saas_platform.Backend.Entities;
using Stripe;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System;

namespace saas_platform.Backend.Controllers
{
    [ApiController]
    [Route("api/billing")]
    [Authorize]
    public class BillingController : ControllerBase
    {
        private readonly PostgresDbContext _db;

        public BillingController(PostgresDbContext db)
        {
            _db = db;
        }

        [HttpPost("upgrade")]
        public async Task<IActionResult> UpgradeToPro()
        {
            var tenantId = User.Claims.First(c => c.Type == "TenantId").Value;

            var subscription = await _db.Subscriptions
                .SingleAsync(x => x.TenantId.ToString() == tenantId);

            if (string.IsNullOrEmpty(subscription.StripeCustomerId))
            {
                var customerService = new CustomerService();
                var customer = await customerService.CreateAsync(
                    new CustomerCreateOptions
                    {
                        Metadata = new Dictionary<string, string>
                        {
                            ["tenantId"] = tenantId
                        }
                    });

                subscription.StripeCustomerId = customer.Id;
                await _db.SaveChangesAsync();
            }

            var subscriptionService = new SubscriptionService();
            var stripeSubscription = await subscriptionService.CreateAsync(
                new SubscriptionCreateOptions
                {
                    Customer = subscription.StripeCustomerId,
                    Items = new List<SubscriptionItemOptions>
                    {
                        new SubscriptionItemOptions
                        {
                            Price = "price_1SrHJKIrKs8ZptWu34ebtErB"
                        }
                    },
                    PaymentBehavior = "default_incomplete"
                });

            subscription.StripeSubscriptionId = stripeSubscription.Id;
            subscription.Plan = SubscriptionPlan.Pro;
            subscription.Status = "Active";

            await _db.SaveChangesAsync();

            return Ok(new
            {
                subscription.Plan,
                subscription.Status,
                subscription.CurrentPeriodEnd
            });
        }
    }
}
