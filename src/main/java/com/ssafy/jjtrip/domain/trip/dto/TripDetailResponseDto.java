package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

public record TripDetailResponseDto(
    Long id,
    String title,
    LocalDate startDate,
    LocalDate endDate,
    TripStatus status,
    List<TripItemResponseDto> tripItems
) {
    public static TripDetailResponseDto from(Trip entity) {
        List<TripItemResponseDto> itemDtos = entity.getTripItems().stream()
                .map(TripItemResponseDto::from)
                .collect(Collectors.toList());

        return new TripDetailResponseDto(
                entity.getId(),
                entity.getTitle(),
                entity.getStartDate(),
                entity.getEndDate(),
                entity.getStatus(),
                itemDtos
        );
    }
}
