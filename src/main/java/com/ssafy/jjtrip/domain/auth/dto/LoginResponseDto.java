package com.ssafy.jjtrip.domain.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "로그인 응답 DTO")
public record LoginResponseDto(

        @Schema(description = "Access Token", example = "eyJhbGciOi...")
        String accessToken,

        @Schema(description = "사용자 이메일", example = "user@example.com")
        String email,

        @Schema(description = "닉네임", example = "윤영")
        String nickname
) {
}
