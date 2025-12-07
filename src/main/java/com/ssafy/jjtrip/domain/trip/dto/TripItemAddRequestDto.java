package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.spot.dto.SpotRequestDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record TripItemAddRequestDto(
        @NotNull
        @Min(value = 1, message = "일차(dayNumber)는 1 이상이어야 합니다.")
        Integer dayNumber,

        @NotNull
        @Min(value = 1, message = "순서(orderIndex)는 1 이상이어야 합니다.")
        Integer orderIndex,

        String memo,

        @Valid @NotNull
        SpotRequestDto spot
) {
}
