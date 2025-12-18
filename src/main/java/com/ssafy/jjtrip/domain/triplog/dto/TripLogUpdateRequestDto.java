package com.ssafy.jjtrip.domain.triplog.dto;

import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;

public record TripLogUpdateRequestDto(
        String title,
        String content,
        TripLogVisibility visibility
) {
}
