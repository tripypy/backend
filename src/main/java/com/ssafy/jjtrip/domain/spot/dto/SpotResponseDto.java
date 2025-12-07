package com.ssafy.jjtrip.domain.spot.dto;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import java.math.BigDecimal;

public record SpotResponseDto(
    Long id,
    String kakaoPlaceId,
    String name,
    String address,
    String category,
    BigDecimal lat,
    BigDecimal lng,
    String placeUrl,
    String thumbnailUrl
) {
    public static SpotResponseDto from(Spot spot) {
        if (spot == null) return null;
        return new SpotResponseDto(
            spot.getId(),
            spot.getKakaoPlaceId(),
            spot.getName(),
            spot.getAddress(),
            spot.getCategory(),
            spot.getLat(),
            spot.getLng(),
            spot.getPlaceUrl(),
            spot.getThumbnailUrl()
        );
    }
}
