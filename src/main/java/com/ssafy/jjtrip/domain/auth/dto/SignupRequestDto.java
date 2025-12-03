package com.ssafy.jjtrip.domain.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "회원가입 요청 DTO")
public record SignupRequestDto(

        @Schema(description = "회원가입 이메일", example = "user@example.com")
        @NotBlank(message = "이메일은 필수 입력값입니다.")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        String email,

        @Schema(description = "비밀번호 (8자 이상)", example = "password1234")
        @NotBlank(message = "비밀번호는 필수 입력값입니다.")
        @Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다.")
        String password,

        @Schema(description = "사용할 닉네임", example = "테스트유저")
        @NotBlank(message = "닉네임은 필수 입력값입니다.")
        String nickname
) {
}
