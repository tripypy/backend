package com.ssafy.jjtrip.domain.triplog.dto;

import java.time.LocalDateTime;
import java.util.List;

public record TripLogDetailResponseDto(
        Long logId,
        String title,
        String content,
        String locationSummary,
        int likeCount,
        int commentCount,
        LocalDateTime createdAt,
        String authorNickname,
        String authorImageUrl,
        Long tripId,
        String tripTitle,
        List<TripLogImageResponseDto> images,
        List<TripLogCommentResponseDto> comments
) {
    public record BaseInfo(
            Long logId,
            String title,
            String content,
            String locationSummary,
            int likeCount,
            int commentCount,
            LocalDateTime createdAt,
            String authorNickname,
            String authorImageUrl,
            Long tripId,
            String tripTitle
    ) {}

    public static TripLogDetailResponseDto from(
            BaseInfo baseInfo, List<TripLogImageResponseDto> images, List<TripLogCommentResponseDto> comments
    ) {
        return new TripLogDetailResponseDto(
                baseInfo.logId(),
                baseInfo.title(),
                baseInfo.content(),
                baseInfo.locationSummary(),
                baseInfo.likeCount(),
                baseInfo.commentCount(),
                baseInfo.createdAt(),
                baseInfo.authorNickname(),
                baseInfo.authorImageUrl(),
                baseInfo.tripId(),
                baseInfo.tripTitle(),
                images,
                comments
        );
    }
}
