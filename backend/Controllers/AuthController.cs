using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

using saas_platform.backend.Dtos;
using saas_platform.backend.Entities;
using saas_platform.Backend.Data;
using saas_platform.Backend.Entities;


namespace saas_platform.backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(UserManager<User> userManager, SignInManager<User> signInManager, PostgresDbContext context, IConfiguration config) : ControllerBase
    {
        private readonly UserManager<User> _userManager = userManager;
        private readonly SignInManager<User> _signInManager = signInManager;
        private readonly IConfiguration _config = config;
        private readonly PostgresDbContext _context = context;

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var user = new User { UserName = dto.Email, Email = dto.Email, Password = dto.Password };
            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);
            await _userManager.AddToRoleAsync(user, "User");
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var confirmationLink = Url.Action(
                nameof(ConfirmEmail),
                "Auth",
                new { userId = user.Id, code = encodedToken },
                protocol: Request.Scheme);
            await _userManager.AddToRoleAsync(user, "User");
            return Ok(new
            {
                Message = "User registered. Please check your email to confirm.",
                ConfirmationLinkForTesting = confirmationLink
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var result = await _signInManager.PasswordSignInAsync(dto.Email, dto.Password, false, false);
            if (!result.Succeeded) return Unauthorized();
            var user = await _userManager.FindByEmailAsync(dto.Email);
            var token = await GenerateJwtToken(user);
            var refreshTokenString = GenerateRefreshToken();

            var refreshEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = refreshTokenString,
                Expires = DateTime.UtcNow.AddDays(7),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"
            };
            await _context.RefreshTokens.AddAsync(refreshEntity);
            await _context.SaveChangesAsync();
            return Ok(new
            {
                Token = token,
                RefreshToken = refreshTokenString
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto request)
        {
            var storedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == request.RefreshToken && !t.IsRevoked);

            if (storedToken == null || storedToken.Expires < DateTime.UtcNow)
                return Unauthorized(new { message = "Invalid or expired refresh token" });

            var user = await _userManager.FindByIdAsync(storedToken.UserId.ToString());
            if (user == null)
                return Unauthorized();

            var newJwt = await GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();

            storedToken.IsRevoked = true;
            storedToken.Revoked = DateTime.UtcNow;
            storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            storedToken.ReplacedByToken = newRefreshToken;

            var newTokenEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = newRefreshToken,
                Expires = DateTime.UtcNow.AddDays(7),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"
            };

            _context.RefreshTokens.Add(newTokenEntity);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                Token = newJwt,
                RefreshToken = newRefreshToken
            });
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
                return Ok(new { Message = "Email confirmed successfully. You can now log in." });
            }

            return BadRequest(new
            {
                Message = "Email confirmation failed.",
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        private async Task<string> GenerateJwtToken(User user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["JwtSettings:Issuer"],
                audience: _config["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword() => Ok("Reset email sent (stub)");
    }
}