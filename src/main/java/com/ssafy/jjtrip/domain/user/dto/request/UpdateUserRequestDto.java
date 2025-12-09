package com.ssafy.jjtrip.domain.user.dto.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserRequestDto {
    private String nickname;
    private String bio;
}
