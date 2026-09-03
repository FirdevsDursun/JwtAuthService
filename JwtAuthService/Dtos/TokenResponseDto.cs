using System;

namespace JwtAuthService.Dtos;

public record TokenResponseDto(string AccessToken, string RefreshToken, DateTime ExpiresAt);
public record RegisterDto(string Username, string Email, string Password);
public record LoginDto(string Username, string Password);
public record RefreshTokenRequestDto(string RefreshToken);