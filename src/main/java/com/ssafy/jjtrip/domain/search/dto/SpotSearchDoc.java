package com.ssafy.jjtrip.domain.search.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.elasticsearch.annotations.Document;
import java.time.LocalDateTime;

@Document(indexName = "trit_spot")
public record SpotSearchDoc(
        @JsonProperty("spotId") Long spotId,
        @JsonProperty("kakaoPlaceId") String kakaoPlaceId,

        @JsonProperty("name") String name,
        @JsonProperty("address") String address,
        @JsonProperty("category") String category,

        @JsonProperty("location") GeoPoint location,
        @JsonProperty("lat") Double lat,
        @JsonProperty("lng") Double lng,

        @JsonProperty("placeUrl") String placeUrl,
        @JsonProperty("thumbnailUrl") String thumbnailUrl,

        @JsonProperty("reviewCount") Integer reviewCount,
        @JsonProperty("averageRating") Double averageRating,

        @JsonProperty("createdAt") LocalDateTime createdAt
) {
    public record GeoPoint(
            @JsonProperty("lat") Double lat,
            @JsonProperty("lon") Double lon
    ) {}
}
