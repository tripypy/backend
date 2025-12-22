package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;
import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

public record TripDetailResponseDto(
    Long id,
    String title,
    Long authorId,
    LocalDate startDate,
    LocalDate endDate,
    TripStatus status,
    TripVisibility visibility,
    String locationSummary,
    boolean isOwner,
    List<TripItemResponseDto> tripItems,
    Long logId
) {
    public static TripDetailResponseDto from(Trip entity, Long currentUserId, Long logId) {
        List<TripItemResponseDto> itemDtos = entity.getTripItems().stream()
                .map(TripItemResponseDto::from)
                .collect(Collectors.toList());

        boolean isOwner = entity.getUserId().equals(currentUserId);

        return new TripDetailResponseDto(
                entity.getId(),
                entity.getTitle(),
                entity.getUserId(),
                entity.getStartDate(),
                entity.getEndDate(),
                entity.getStatus(),
                entity.getVisibility(),
                entity.getLocationSummary(),
                isOwner,
                itemDtos,
                logId
        );
    }
}
