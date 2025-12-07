package com.ssafy.jjtrip.domain.trip.dto;

import jakarta.validation.constraints.NotNull;
import java.util.List;

public record DayItemsDto(
        @NotNull
        Integer dayNumber,

        @NotNull
        List<Long> items
) {
}
