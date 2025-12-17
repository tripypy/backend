package com.ssafy.jjtrip.domain.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SignupRequestDto(
        
        @NotBlank(message = "이메일은 필수 입력값입니다.")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        String email,

        @NotBlank(message = "비밀번호는 필수 입력값입니다.")
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$", message = "비밀번호는 8자 이상이어야 하며, 영어 대문자, 소문자, 숫자, 특수문자를 모두 포함해야 합니다.")
        String password,

        @NotBlank(message = "닉네임은 필수 입력값입니다.")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "닉네임은 영어, 숫자, 언더스코어(_)만 사용 가능합니다.")
        String nickname
) {
}
