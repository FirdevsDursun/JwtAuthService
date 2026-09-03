using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuthService.Data;
using JwtAuthService.Dtos;
using JwtAuthService.Entities;
using JwtAuthService.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthService.Services;

public class AuthService : IAuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthService(AppDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    public async Task<bool> RegisterAsync(RegisterDto dto)
    {
        if (await _context.Users.AnyAsync(u => u.Username == dto.Username || u.Email == dto.Email))
            return false;

        var user = new ApplicationUser
        {
            Username = dto.Username,
            Email = dto.Email,
            PasswordHash = PasswordHasher.HashPassword(dto.Password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<TokenResponseDto?> LoginAsync(LoginDto dto)
    {
        var user = await _context.Users.Include(u => u.RefreshTokens)
            .FirstOrDefaultAsync(u => u.Username == dto.Username);

        if (user == null || !PasswordHasher.VerifyPassword(dto.Password, user.PasswordHash))
            return null;

        return await GenerateAndSaveTokens(user);
    }

    public async Task<TokenResponseDto?> RefreshTokenAsync(string refreshTokenStr)
    {
        var token = await _context.RefreshTokens.Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == refreshTokenStr);

        if (token == null || token.IsRevoked || token.ExpiresAt <= DateTime.UtcNow)
            return null;

        token.IsRevoked = true;
        return await GenerateAndSaveTokens(token.User);
    }

    private async Task<TokenResponseDto> GenerateAndSaveTokens(ApplicationUser user)
    {
        var jwtToken = CreateJwtToken(user);
        var refreshToken = new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            UserId = user.Id
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();

        return new TokenResponseDto(jwtToken, refreshToken.Token, DateTime.UtcNow.AddMinutes(15));
    }

    private string CreateJwtToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}