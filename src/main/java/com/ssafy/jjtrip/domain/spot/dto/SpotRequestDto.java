package com.ssafy.jjtrip.domain.spot.dto;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.math.BigDecimal;

@Builder
public record SpotRequestDto(
        @NotBlank
        String kakaoPlaceId,

        @NotBlank
        String name,

        String address,
        String category,

        @NotNull
        BigDecimal lat,

        @NotNull
        BigDecimal lng,

        String placeUrl,
        String thumbnailUrl
) {
    public Spot toEntity() {
        return Spot.builder()
                .kakaoPlaceId(this.kakaoPlaceId)
                .name(this.name)
                .address(this.address)
                .category(this.category)
                .lat(this.lat)
                .lng(this.lng)
                .placeUrl(this.placeUrl)
                .thumbnailUrl(this.thumbnailUrl)
                .build();
    }
}
