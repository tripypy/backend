package com.ssafy.jjtrip.domain.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSearchResponseDto {
    private Long id;
    private String nickname;
    private String profileImageUrl;
}
