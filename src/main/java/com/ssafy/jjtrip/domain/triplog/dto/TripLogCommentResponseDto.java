package com.ssafy.jjtrip.domain.triplog.dto;

import java.time.LocalDateTime;

public record TripLogCommentResponseDto(
        Long commentId,
        String authorNickname,
        String authorImageUrl,
        String content,
        LocalDateTime createdAt
) {
}
