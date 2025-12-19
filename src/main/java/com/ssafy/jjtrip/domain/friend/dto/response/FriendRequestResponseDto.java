package com.ssafy.jjtrip.domain.friend.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FriendRequestResponseDto {
    private Long requestId;
    private SimpleUserInfoDto user; // 요청을 보낸 사람 또는 받은 사람
    private LocalDateTime createdAt;
}