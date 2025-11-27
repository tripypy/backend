package com.ssafy.jjtrip.domain.auth.dto;

public record TokenInfo(
        String accessToken,
        String refreshToken
) {
}
