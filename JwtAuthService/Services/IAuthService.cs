using System.Threading.Tasks;
using JwtAuthService.Dtos;

namespace JwtAuthService.Services;

public interface IAuthService
{
    Task<bool> RegisterAsync(RegisterDto dto);
    Task<TokenResponseDto?> LoginAsync(LoginDto dto);
    Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken);
}