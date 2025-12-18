package com.ssafy.jjtrip.domain.triplog.dto;

import java.time.LocalDateTime;

import java.util.List;

public record TripLogCommentResponseDto(
        Long commentId,
        String authorNickname,
        String authorImageUrl,
        String content,
        Long parentId,
        LocalDateTime createdAt,
        List<TripLogCommentResponseDto> replies
) {
    public static TripLogCommentResponseDto from(TripLogCommentFlatDto flatDto, List<TripLogCommentResponseDto> replies) {
        return new TripLogCommentResponseDto(
            flatDto.commentId(),
            flatDto.authorNickname(),
            flatDto.authorImageUrl(),
            flatDto.content(),
            flatDto.parentId(),
            flatDto.createdAt(),
            replies
        );
    }
}
