package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.spot.dto.SpotRequestDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record TripItemsUpdateRequestDto(
        @NotNull
        @Valid
        List<Day> days
) {
    public record Day(
            @NotNull
            Integer dayNumber,

            @NotNull @Valid
            List<ItemSync> items
    ) {
    }

    public record ItemSync(
            Long tripItemId,

            @Valid
            SpotRequestDto spot,

            String memo
    ) {
    }
}
