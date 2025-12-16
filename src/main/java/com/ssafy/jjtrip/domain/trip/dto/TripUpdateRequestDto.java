package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;
import java.time.LocalDate;

public record TripUpdateRequestDto(
    String title,
    LocalDate startDate,
    LocalDate endDate,
    TripStatus status,
    TripVisibility visibility
) {
}
