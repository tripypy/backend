package com.ssafy.jjtrip.domain.friend.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FriendRequestRequestDto {
    @NotNull(message = "친구요청을 받는 사용자 ID는 필수입니다.")
    private Long receiverId;
}
