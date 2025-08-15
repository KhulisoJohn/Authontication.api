using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authentication.DTOs;
using Authentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IConfiguration _config;

    public AuthController(UserManager<User> userManager, IConfiguration config)
    {
        _userManager = userManager;
        _config = config;
    }

    [HttpPost("register")]
public async Task<IActionResult> Register(UserRegisterDto dto)
{
    var user = new User { UserName = dto.UserName, Email = dto.Email };
    var result = await _userManager.CreateAsync(user, dto.Password);

    if (!result.Succeeded)
        return BadRequest(result.Errors);

    
    return Ok(new { message = "Registration successful" });
}

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserLoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
            return Unauthorized();

        return Ok(await GenerateToken(user));
    }

    private async Task<AuthResultDto> GenerateToken(User user)
    {
        var jwtKey = Environment.GetEnvironmentVariable("JwtSettings__Secret")!;
        var jwtIssuer = Environment.GetEnvironmentVariable("JwtSettings__Issuer")!;
        var jwtAudience = Environment.GetEnvironmentVariable("JwtSettings__Audience")!;
        var jwtExpiry = int.Parse(Environment.GetEnvironmentVariable("JwtSettings__ExpiresInMinutes") ?? "60");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new Claim(ClaimTypes.Name, user.UserName ?? "")
        };

        var token = new JwtSecurityToken(
            issuer: jwtIssuer,
            audience: jwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(jwtExpiry),
            signingCredentials: creds
        );

        return new AuthResultDto(
            new JwtSecurityTokenHandler().WriteToken(token),
             user.Id.ToString(),
            user.UserName ?? "",
            user.Email ?? "",
            user.Bio
        );
    }
}
