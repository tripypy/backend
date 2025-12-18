package com.ssafy.jjtrip.domain.triplog.dto.request;

import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;

public record TripLogUpdateRequestDto(
        String title,
        String content,
        TripLogVisibility visibility
) {
}
