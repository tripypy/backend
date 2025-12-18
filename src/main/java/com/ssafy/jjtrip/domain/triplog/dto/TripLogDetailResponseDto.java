package com.ssafy.jjtrip.domain.triplog.dto;

import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;
import java.time.LocalDateTime;
import java.util.List;

public record TripLogDetailResponseDto(
        Long logId,
        String title,
        String content,
        String locationSummary,
        LocalDateTime createdAt,
        String authorNickname,
        String authorImageUrl,
        TripLogVisibility visibility,
        Long tripId,
        String tripTitle,
        List<TripLogImageResponseDto> images,
        List<TripLogCommentResponseDto> comments,
        int likeCount,
        int commentCount
) {
    public record BaseInfo(
            Long logId,
            String title,
            String content,
            String locationSummary,
            LocalDateTime createdAt,
            Long authorId,
            String authorNickname,
            String authorImageUrl,
            TripLogVisibility visibility,
            Long tripId,
            String tripTitle
    ) {}

    public static TripLogDetailResponseDto from(
            BaseInfo baseInfo,
            List<TripLogImageResponseDto> images,
            List<TripLogCommentResponseDto> comments,
            int likeCount,
            int commentCount
    ) {
        return new TripLogDetailResponseDto(
                baseInfo.logId(),
                baseInfo.title(),
                baseInfo.content(),
                baseInfo.locationSummary(),
                baseInfo.createdAt(),
                baseInfo.authorNickname(),
                baseInfo.authorImageUrl(),
                baseInfo.visibility(),
                baseInfo.tripId(),
                baseInfo.tripTitle(),
                images,
                comments,
                likeCount,
                commentCount
        );
    }
}
