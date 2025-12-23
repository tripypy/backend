package com.ssafy.jjtrip.domain.triplog.dto.response;

import java.time.LocalDateTime;

public record TripLogCommentFlatDto(
        Long commentId,
        Long authorId,
        String authorNickname,
        String authorImageUrl,
        String content,
        Long parentId,
        boolean isDeleted,
        LocalDateTime createdAt
) {
}
