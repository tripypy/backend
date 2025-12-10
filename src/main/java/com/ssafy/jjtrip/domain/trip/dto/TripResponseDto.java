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
    boolean isOwner,
    int spots,
    List<String> tags,
    List<SpotPreviewDto> spotPreviews,
    LocalDate completedDate
) {
    public static TripResponseDto from(Trip entity, boolean isOwner, int spots, List<String> tags, List<SpotPreviewDto> spotPreviews) {
        return new TripResponseDto(
                entity.getId(),
                entity.getTitle(),
                entity.getStartDate(),
                entity.getEndDate(),
                entity.getStatus(),
                entity.getVisibility(),
                isOwner,
                spots,
                tags,
                spotPreviews,
                entity.getStatus() == TripStatus.COMPLETED ? entity.getEndDate() : null
        );
    }

    public record SpotPreviewDto(String name) {}
}
