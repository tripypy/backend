package com.ssafy.jjtrip.domain.spot.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import java.math.BigDecimal;

public record SpotReviewUpdateRequestDto(
    @DecimalMin(value = "0.5", message = "점수는 최소 0.5점 이상이어야 합니다.")
    @DecimalMax(value = "5.0", message = "점수는 최대 5.0점 이하여야 합니다.")
    BigDecimal rating,

    String content
) {}
