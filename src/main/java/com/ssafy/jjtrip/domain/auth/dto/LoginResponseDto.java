package com.ssafy.jjtrip.domain.auth.dto;

public record LoginResponseDto(
        String accessToken,
        long expiresIn,
        String email,
        String nickname
) {
}
