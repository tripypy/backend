package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.spot.dto.SpotResponseDto;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;

public record TripItemResponseDto(
    Long id,
    int dayNumber,
    int orderIndex,
    SpotResponseDto spot
) {
    public static TripItemResponseDto from(TripItem entity) {
        return new TripItemResponseDto(
                entity.getId(),
                entity.getDayNumber(),
                entity.getOrderIndex(),
                SpotResponseDto.from(entity.getSpot())
        );
    }
}
