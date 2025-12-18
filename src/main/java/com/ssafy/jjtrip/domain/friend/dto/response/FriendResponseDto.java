package com.ssafy.jjtrip.domain.friend.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FriendResponseDto {
    private Long userId;
    private String nickname;
    private String profileImageUrl;
    private String bio;
}
