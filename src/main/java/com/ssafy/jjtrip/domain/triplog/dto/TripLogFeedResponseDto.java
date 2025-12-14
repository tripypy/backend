package com.ssafy.jjtrip.domain.triplog.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.List;

public record TripLogFeedResponseDto(
        Long logId,
        Long authorId,
        String authorNickname,
        String authorImageUrl,
        String title,
        String content,
        String locationSummary,
        int likeCount,
        int commentCount,
        boolean liked,
        List<TripLogImageResponseDto> images,
        @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
        LocalDateTime createdAt
) {

    public static TripLogFeedResponseDto from(FeedData data, List<TripLogImageResponseDto> images) {
        return new TripLogFeedResponseDto(
                data.logId,
                data.authorId,
                data.authorNickname,
                data.authorImageUrl,
                data.title,
                data.content,
                data.locationSummary,
                data.likeCount,
                data.commentCount,
                data.liked,
                images,
                data.createdAt
        );
    }

    public record FeedData(
            Long logId,
            Long authorId,
            String authorNickname,
            String authorImageUrl,
            String title,
            String content,
            String locationSummary,
            int likeCount,
            int commentCount,
            boolean liked,
            @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
            LocalDateTime createdAt
    ) {
    }
}
