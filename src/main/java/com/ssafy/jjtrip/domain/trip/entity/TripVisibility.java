package com.ssafy.jjtrip.domain.trip.entity;

import lombok.Getter;

@Getter
public enum TripVisibility {

    PUBLIC("전체 공개"),
    PRIVATE("나만 보기");

    private final String description;

    TripVisibility(String description) {
        this.description = description;
    }
}
