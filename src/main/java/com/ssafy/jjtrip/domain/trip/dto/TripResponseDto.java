package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;

import java.time.LocalDate;

public record TripResponseDto(
    Long id,
    String title,
    LocalDate startDate,
    LocalDate endDate,
    TripStatus status,
    TripVisibility visibility
) {
    public static TripResponseDto from(Trip entity) {
        return new TripResponseDto(
                entity.getId(),
                entity.getTitle(),
                entity.getStartDate(),
                entity.getEndDate(),
                entity.getStatus(),
                entity.getVisibility()
        );
    }
}
