using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

using saas_platform.backend.Data;
using saas_platform.backend.Dtos;
using saas_platform.backend.Entities;

namespace saas_platform.backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        PostgresDbContext context,
        IConfiguration config,
        IMemoryCache cache,
        ILogger<AuthController> logger
    ) : ControllerBase
    {
        private readonly UserManager<User> _userManager = userManager;
        private readonly SignInManager<User> _signInManager = signInManager;
        private readonly IConfiguration _config = config;
        private readonly PostgresDbContext _context = context;
        private readonly IMemoryCache _cache = cache;
        private readonly ILogger<AuthController> _logger = logger;

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            _logger.LogInformation("Register attempt for {Email}", dto.Email);

            var user = new User { UserName = dto.Email, Email = dto.Email };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                _logger.LogWarning(
                    "Register failed for {Email}: {Errors}",
                    dto.Email,
                    string.Join(", ", result.Errors.Select(e => e.Description))
                );
                return BadRequest(result.Errors);
            }

            await _userManager.AddToRoleAsync(user, "User");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var confirmationLink = Url.Action(
                nameof(ConfirmEmail),
                "Auth",
                new { userId = user.Id, code = encodedToken },
                protocol: Request.Scheme
            );

            var subscription = await _context.Subscriptions.SingleOrDefaultAsync(x =>
                x.TenantId == user.Id
            );

            if (subscription == null)
            {
                subscription = new Subscription
                {
                    TenantId = user.Id,
                    Plan = SubscriptionPlan.Free,
                    Status = "Active",
                    CreatedAt = DateTime.UtcNow,
                };
                await _context.Subscriptions.AddAsync(subscription);
                await _context.SaveChangesAsync();
            }

            _logger.LogInformation("User created {UserId}", user.Id);

            return Ok(
                new
                {
                    Message = "User registered. Please check your email to confirm.",
                    ConfirmationLinkForTesting = confirmationLink,
                }
            );
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            _logger.LogInformation("Login attempt for {Email}", dto.Email);

            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                _logger.LogWarning("Login failed: user not found for {Email}", dto.Email);
                return Unauthorized();
            }

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Login blocked: email not confirmed for {Email}", dto.Email);
                return Unauthorized(new { message = "Email not confirmed. Check inbox." });
            }

            var result = await _signInManager.PasswordSignInAsync(
                dto.Email,
                dto.Password,
                false,
                lockoutOnFailure: true
            );
            if (!result.Succeeded)
            {
                _logger.LogWarning("Login failed for {Email}", dto.Email);
                return Unauthorized();
            }

            var token = await GenerateJwtToken(user);
            var refreshTokenString = GenerateRefreshToken();
            var refreshHash = ComputeSha256Hash(refreshTokenString);

            var refreshEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = refreshHash,
                Expires = DateTime.UtcNow.AddDays(7),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            };
            await _context.RefreshTokens.AddAsync(refreshEntity);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Login success: issued tokens for {UserId}", user.Id);

            return Ok(new { Token = token, RefreshToken = refreshTokenString });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto request)
        {
            var requestHash = ComputeSha256Hash(request.RefreshToken);

            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t =>
                t.Token == requestHash && !t.IsRevoked
            );

            if (storedToken == null || storedToken.Expires < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh failed: invalid or expired refresh token");
                return Unauthorized(new { message = "Invalid or expired refresh token" });
            }

            var user = await _userManager.FindByIdAsync(storedToken.UserId.ToString());
            if (user == null)
            {
                _logger.LogWarning("Refresh failed: user not found {UserId}", storedToken.UserId);
                return Unauthorized();
            }

            var newJwt = await GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();
            var newRefreshHash = ComputeSha256Hash(newRefreshToken);

            storedToken.IsRevoked = true;
            storedToken.Revoked = DateTime.UtcNow;
            storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            storedToken.ReplacedByToken = newRefreshHash;

            var newTokenEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = newRefreshHash,
                Expires = DateTime.UtcNow.AddDays(7),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            };

            _context.RefreshTokens.Add(newTokenEntity);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Refresh success for {UserId}", user.Id);

            return Ok(new { Token = newJwt, RefreshToken = newRefreshToken });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RevokeTokenDto dto)
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var hash = ComputeSha256Hash(dto.RefreshToken);
            var stored = await _context.RefreshTokens.FirstOrDefaultAsync(t =>
                t.Token == hash && t.UserId == userId && !t.IsRevoked
            );
            if (stored == null)
                return NotFound();

            stored.IsRevoked = true;
            stored.Revoked = DateTime.UtcNow;
            stored.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _context.SaveChangesAsync();

            _logger.LogInformation("Logout: token revoked for {UserId}", userId);
            return Ok(new { message = "Logged out (token revoked)" });
        }

        [HttpGet("sessions")]
        [Authorize]
        public async Task<IActionResult> Sessions()
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var tokens = await _context
                .RefreshTokens.Where(t => t.UserId == userId)
                .OrderByDescending(t => t.Created)
                .Select(t => new
                {
                    t.Id,
                    t.Expires,
                    t.IsRevoked,
                    t.Created,
                    t.CreatedByIp,
                    t.Revoked,
                    t.RevokedByIp,
                })
                .ToListAsync();

            return Ok(tokens);
        }

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return Unauthorized();

            var result = await _userManager.ChangePasswordAsync(
                user,
                dto.CurrentPassword,
                dto.NewPassword
            );
            if (!result.Succeeded)
            {
                _logger.LogWarning("Change password failed for {UserId}", userId);
                return BadRequest(result.Errors);
            }

            _logger.LogInformation("Password changed for {UserId}", userId);
            return Ok(new { message = "Password changed" });
        }

        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset(
            [FromBody] ResetPasswordRequestDto dto
        )
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return Ok(new { message = "If the email exists, a reset link was sent." });

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetLink = Url.Action(
                nameof(ResetPassword),
                "Auth",
                new { userId = user.Id, token = encodedToken },
                Request.Scheme
            );

            _logger.LogInformation("Password reset requested for {UserId}", user.Id);
            return Ok(new { ResetLinkForTesting = resetLink });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
                return NotFound();

            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(dto.Token));
            var result = await _userManager.ResetPasswordAsync(user, token, dto.NewPassword);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Password reset failed for {UserId}", dto.UserId);
                return BadRequest(result.Errors);
            }

            _logger.LogInformation("Password reset success for {UserId}", dto.UserId);
            return Ok(new { message = "Password reset successful" });
        }

        [HttpPost("enable-2fa")]
        [Authorize]
        public async Task<IActionResult> Enable2Fa([FromBody] Enable2FaDto _)
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var code = new Random().Next(100000, 999999).ToString();
            _cache.Set($"2fa:{userId}", code, TimeSpan.FromMinutes(10));

            _logger.LogInformation("2FA enable challenge issued for {UserId}", userId);
            return Ok(new { Message = "2FA challenge generated (mock)", CodeForTesting = code });
        }

        [HttpPost("verify-2fa")]
        [Authorize]
        public async Task<IActionResult> Verify2Fa([FromBody] Verify2FaDto dto)
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (!_cache.TryGetValue<string>($"2fa:{userId}", out var expected))
                return BadRequest(new { message = "No 2FA challenge found or code expired" });

            if (dto.Code != expected)
                return BadRequest(new { message = "Invalid code" });

            var user = await _userManager.FindByIdAsync(userId.ToString());
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            _cache.Remove($"2fa:{userId}");

            _logger.LogInformation("2FA enabled for {UserId}", userId);
            return Ok(new { message = "2FA enabled (mock)" });
        }

        [HttpPost("add-phone")]
        [Authorize]
        public async Task<IActionResult> AddPhone([FromBody] AddPhoneDto dto)
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var code = new Random().Next(100000, 999999).ToString();
            _cache.Set($"phone:{userId}:{dto.PhoneNumber}", code, TimeSpan.FromMinutes(10));

            _logger.LogInformation("Phone verification challenge created for {UserId}", userId);
            return Ok(
                new { Message = "Phone verification code generated (mock)", CodeForTesting = code }
            );
        }

        [HttpPost("verify-phone")]
        [Authorize]
        public async Task<IActionResult> VerifyPhone([FromBody] VerifyPhoneDto dto)
        {
            var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (!_cache.TryGetValue<string>($"phone:{userId}:{dto.PhoneNumber}", out var expected))
                return BadRequest(new { message = "No verification found or code expired" });

            if (dto.Code != expected)
                return BadRequest(new { message = "Invalid code" });

            var user = await _userManager.FindByIdAsync(userId.ToString());
            await _userManager.SetPhoneNumberAsync(user, dto.PhoneNumber);
            user.PhoneNumberConfirmed = true;
            await _userManager.UpdateAsync(user);

            _cache.Remove($"phone:{userId}:{dto.PhoneNumber}");

            _logger.LogInformation("Phone number verified and set for {UserId}", userId);
            return Ok(new { message = "Phone verified (mock)" });
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
                return BadRequest(new { Message = "Invalid confirmation request" });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { Message = "User not found" });

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

            var result = await _userManager.ConfirmEmailAsync(user, code);

            if (result.Succeeded)
            {
                _logger.LogInformation("Email confirmed for {UserId}", userId);
                return Ok(new { Message = "Email confirmed successfully. You can now log in." });
            }

            _logger.LogWarning("Email confirmation failed for {UserId}", userId);
            return BadRequest(
                new
                {
                    Message = "Email confirmation failed.",
                    Errors = result.Errors.Select(e => e.Description),
                }
            );
        }

        private async Task<string> GenerateJwtToken(User user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new("TenantId", user.Id.ToString()),
            };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"])
            );
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["JwtSettings:Issuer"],
                audience: _config["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private static string ComputeSha256Hash(string raw)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return Convert.ToBase64String(bytes);
        }
    }
}
