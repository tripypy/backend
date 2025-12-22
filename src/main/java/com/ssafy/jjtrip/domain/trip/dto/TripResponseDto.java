package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;

import java.time.LocalDate;
import java.util.List;

public record TripResponseDto(
    Long id,
    String title,
    LocalDate startDate,
    LocalDate endDate,
    TripStatus status,
    TripVisibility visibility,
    String locationSummary,
    boolean isOwner,
    int spots,
    List<String> tags,
    List<SpotPreviewDto> spotPreviews,
    Long logId
) {
    public static TripResponseDto from(Trip entity, boolean isOwner, int spots, List<String> tags, List<SpotPreviewDto> spotPreviews, Long logId) {
        return new TripResponseDto(
                entity.getId(),
                entity.getTitle(),
                entity.getStartDate(),
                entity.getEndDate(),
                entity.getStatus(),
                entity.getVisibility(),
                entity.getLocationSummary(),
                isOwner,
                spots,
                tags,
                spotPreviews,
                logId
        );
    }

    public record SpotPreviewDto(String name) {}
}
