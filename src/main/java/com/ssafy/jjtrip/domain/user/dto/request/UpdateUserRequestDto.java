package com.ssafy.jjtrip.domain.user.dto.request;

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserRequestDto {
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "닉네임은 영어, 숫자, 언더스코어(_)만 사용 가능합니다.")
    private String nickname;
    private String bio;
}
