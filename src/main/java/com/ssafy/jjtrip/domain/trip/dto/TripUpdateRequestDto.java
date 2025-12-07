package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public record TripUpdateRequestDto(
    @NotBlank(message = "여행 제목은 필수입니다.")
    String title,

    LocalDate startDate,

    LocalDate endDate,

    @NotNull(message = "공개 여부는 필수입니다.")
    TripStatus status
) {
}