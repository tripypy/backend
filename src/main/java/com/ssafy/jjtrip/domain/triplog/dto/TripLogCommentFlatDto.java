package com.ssafy.jjtrip.domain.triplog.dto;

import java.time.LocalDateTime;

public record TripLogCommentFlatDto(
        Long commentId,
        String authorNickname,
        String authorImageUrl,
        String content,
        Long parentId,
        LocalDateTime createdAt
) {
}
