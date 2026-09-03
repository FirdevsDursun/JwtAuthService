using JwtAuthService.Dtos;
using JwtAuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var result = await _authService.RegisterAsync(dto);
        return result ? Ok("Kullanıcı oluşturuldu.") : BadRequest("Kullanıcı zaten mevcut.");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        var result = await _authService.LoginAsync(dto);
        return result != null ? Ok(result) : Unauthorized("Geçersiz kullanıcı adı veya şifre.");
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshTokenRequestDto dto)
    {
        var result = await _authService.RefreshTokenAsync(dto.RefreshToken);
        return result != null ? Ok(result) : Unauthorized("Geçersiz veya süresi dolmuş Refresh Token.");
    }

    [Authorize]
    [HttpGet("protected")]
    public IActionResult ProtectedEndpoint()
    {
        return Ok($"Güvenli alana erişildi. Kullanıcı: {User.Identity?.Name}");
    }
}