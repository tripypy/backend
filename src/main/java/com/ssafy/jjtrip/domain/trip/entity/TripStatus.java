package com.ssafy.jjtrip.domain.trip.entity;

import lombok.Getter;

@Getter
public enum TripStatus {

    DRAFT("초안"),
    PUBLIC("공개"),
    PRIVATE("비공개");

    private final String description;

    TripStatus(String description) {
        this.description = description;
    }
}
