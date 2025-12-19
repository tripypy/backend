package com.ssafy.jjtrip.domain.spot.dto;

import com.ssafy.jjtrip.domain.spot.entity.SpotReview;
import java.math.BigDecimal;
import java.time.LocalDateTime;

public record SpotReviewResponseDto(
    Long id,
    Long spotId,
    Long userId, // Or UserSummaryDto if checking User info
    String userNickname, // Often needed for UI
    String userProfileImage, // Often needed for UI
    BigDecimal rating,
    String content,
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {
    public static SpotReviewResponseDto from(SpotReview review, String nickname, String profileImage) {
        return new SpotReviewResponseDto(
            review.getId(),
            review.getSpotId(),
            review.getUserId(),
            nickname,
            profileImage,
            review.getRating(),
            review.getContent(),
            review.getCreatedAt(),
            review.getUpdatedAt()
        );
    }
}
