package com.ssafy.jjtrip.domain.auth.dto;

public record TokenResponseDto(
        String accessToken,
        long expiresIn
) {
}
