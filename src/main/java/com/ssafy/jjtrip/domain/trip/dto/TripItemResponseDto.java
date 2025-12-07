package com.ssafy.jjtrip.domain.trip.dto;

import com.ssafy.jjtrip.domain.trip.entity.TripItem;

public record TripItemResponseDto(
    Long id,
    Long spotId,
    int dayNumber,
    int orderIndex,
    String memo
) {
    public static TripItemResponseDto from(TripItem entity) {
        return new TripItemResponseDto(
                entity.getId(),
                entity.getSpotId(),
                entity.getDayNumber(),
                entity.getOrderIndex(),
                entity.getMemo()
        );
    }
}
