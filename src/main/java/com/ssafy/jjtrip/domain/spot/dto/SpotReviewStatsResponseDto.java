package com.ssafy.jjtrip.domain.spot.dto;

import java.math.BigDecimal;

public record SpotReviewStatsResponseDto(
    BigDecimal averageRating,
    long reviewCount
) {}
