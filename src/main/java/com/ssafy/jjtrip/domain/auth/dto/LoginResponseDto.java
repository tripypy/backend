package com.ssafy.jjtrip.domain.auth.dto;

public record LoginResponseDto(
        String accessToken,
        String email,
        String nickname
) {
}
