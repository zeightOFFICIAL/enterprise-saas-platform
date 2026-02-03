using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver.Core.Configuration;

using saas_platform.backend.Data;
using saas_platform.backend.Entities;
using saas_platform.backend.Services;

using Serilog;
using Stripe;

var builder = WebApplication.CreateBuilder(args);

static void LoadDotEnv(string filePath)
{
    if (!System.IO.File.Exists(filePath))
        return;

    var lines = System.IO.File.ReadAllLines(filePath);
    foreach (var raw in lines)
    {
        var line = raw.Trim();
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            continue;

        if (line.Contains('='))
        {
            var idx = line.IndexOf('=');
            var key = line[..idx].Trim();
            var value = line[(idx + 1)..].Trim().Trim('"');
            if (!string.IsNullOrWhiteSpace(key) && Environment.GetEnvironmentVariable(key) is null)
                Environment.SetEnvironmentVariable(key, value);
            continue;
        }
    }
}

static void LoadDotEnvPositional(string filePath)
{
    if (!System.IO.File.Exists(filePath))
        return;

    var values = System.IO.File.ReadAllLines(filePath)
        .Select(l => l.Trim())
        .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith('#'))
        .ToList();

    if (values.Count >= 1 && Environment.GetEnvironmentVariable("JwtSettings__SecretKey") is null)
        Environment.SetEnvironmentVariable("JwtSettings__SecretKey", values[0]);
    if (values.Count >= 2 && Environment.GetEnvironmentVariable("Stripe__SecretKey") is null)
        Environment.SetEnvironmentVariable("Stripe__SecretKey", values[1]);
    if (values.Count >= 3 && Environment.GetEnvironmentVariable("Stripe__WebhookSecret") is null)
        Environment.SetEnvironmentVariable("Stripe__WebhookSecret", values[2]);
}

var envPath = Path.Combine(builder.Environment.ContentRootPath, ".env");
LoadDotEnv(envPath);
LoadDotEnvPositional(envPath);

var slnEnvPath = Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, "..", ".env"));
LoadDotEnv(slnEnvPath);
LoadDotEnvPositional(slnEnvPath);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .Enrich.FromLogContext()
    .WriteTo.File(
        "logs/auth-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14
    )
    .CreateLogger();

builder.Host.UseSerilog();

builder.Services.AddDbContext<PostgresDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("PostgresConnection"))
);
builder.Services.AddOpenApi();
builder.Services.AddSingleton<MongoService>();
builder.Services.AddMemoryCache();
builder.Services.AddControllers();

builder
    .Services.AddIdentity<User, IdentityRole<Guid>>(options =>
    {
        options.SignIn.RequireConfirmedEmail = true;
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<PostgresDbContext>()
    .AddDefaultTokenProviders();

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var jwtSecret = Environment.GetEnvironmentVariable("JwtSettings__SecretKey") ?? jwtSettings["SecretKey"];
if (string.IsNullOrWhiteSpace(jwtSecret) || jwtSecret.Length < 32)
{
    throw new InvalidOperationException(
        $"JwtSettings:SecretKey must be provided (>= 32 chars). Configure it via environment variables, user secrets, or a .env file. Looked for .env in '{envPath}' and '{slnEnvPath}'."
    );
}
// Always prefer env var (from .env) over appsettings for secrets.
// This ensures appsettings.json can remain secret-free.
builder
    .Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSecret)
            ),
        };
    });
builder
    .Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"))
    .AddPolicy("AdminOrAbove", policy => policy.RequireRole("Admin", "AdminLevel2"))
    .AddPolicy("ModeratorOrAbove", policy => policy.RequireRole("Moderator", "Admin", "AdminLevel2"))
    .AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin", "AdminLevel2", "Moderator"));
builder.Services.AddAuthorization();

var app = builder.Build();
var stripeKey = Environment.GetEnvironmentVariable("Stripe__SecretKey") ?? builder.Configuration["Stripe:SecretKey"];
if (string.IsNullOrWhiteSpace(stripeKey))
{
    throw new InvalidOperationException(
        $"Stripe:SecretKey must be provided. Configure it via environment variables, user secrets, or a .env file. Looked for .env in '{envPath}' and '{slnEnvPath}'."
    );
}
StripeConfiguration.ApiKey = stripeKey;

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
    await RoleSeeder.SeedRoles(roleManager);
}

app.Run();
