package com.ssafy.jjtrip.domain.user.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserProfileResponseDto {
    private Long id;
    private String email;
    private String nickname;
    private String profileImageUrl;
}
