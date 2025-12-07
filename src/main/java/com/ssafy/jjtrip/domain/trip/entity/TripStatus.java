package com.ssafy.jjtrip.domain.trip.entity;

import lombok.Getter;

@Getter
public enum TripStatus {

    DRAFT(1L, "작성 중"),
    PLANNED(2L, "계획 완료"),
    COMPLETED(3L, "여행 완료");

    private final Long id;
    private final String description;

    TripStatus(Long id, String description) {
        this.id = id;
        this.description = description;
    }
}
