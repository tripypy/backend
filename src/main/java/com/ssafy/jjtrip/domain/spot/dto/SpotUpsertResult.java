package com.ssafy.jjtrip.domain.spot.dto;

import com.ssafy.jjtrip.domain.spot.entity.Spot;

public record SpotUpsertResult(
        Spot spot,
        boolean isNew
) {
}
