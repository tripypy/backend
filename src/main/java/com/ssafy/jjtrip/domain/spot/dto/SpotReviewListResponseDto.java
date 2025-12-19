package com.ssafy.jjtrip.domain.spot.dto;

import java.util.List;

public record SpotReviewListResponseDto(
    SpotReviewResponseDto myReview,
    List<SpotReviewResponseDto> reviews
) {
}
