using saas_platform.Backend.Entities;
using Microsoft.EntityFrameworkCore;

namespace saas_platform.Backend.Data
{
    public class PostgresDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Subscription> Subscriptions { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseNpgsql("Host=localhost;Database=saasdb;Username=saasuser;Password=saaspassword");
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Subscription>()
                .HasOne<User>()
                .WithMany()
                .HasForeignKey(s => s.UserId);
        }
    }
}