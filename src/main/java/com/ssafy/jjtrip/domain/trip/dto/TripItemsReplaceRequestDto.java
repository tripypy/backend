package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.spot.dto.SpotRequestDto;
import com.ssafy.jjtrip.domain.trip.exception.TripErrorCode;
import com.ssafy.jjtrip.domain.trip.exception.TripException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record TripItemsReplaceRequestDto(
        @NotNull @Valid List<Day> days
) {
    public record Day(
            @NotNull Integer dayNumber,
            @NotNull @Valid List<Item> items
    ) {}

    public record Item(
            Long spotId,
            @Valid SpotRequestDto spot
    ) {
        public void validate() {
            boolean hasId = spotId != null;
            boolean hasSpot = spot != null;

            if (hasId == hasSpot) { // 둘 다 있거나 둘 다 없으면 에러
                throw new TripException(TripErrorCode.INVALID_ITEMS_REPLACE_REQUEST);
            }
        }
    }
}
