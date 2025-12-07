package com.ssafy.jjtrip.domain.trip.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record TripItemsUpdateRequestDto(
        @NotNull
        @Valid
        List<DayItemsDto> days
) {
}
