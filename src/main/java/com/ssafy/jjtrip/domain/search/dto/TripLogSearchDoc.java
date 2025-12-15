package com.ssafy.jjtrip.domain.search.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.elasticsearch.annotations.Document;
import java.time.LocalDateTime;

@Document(indexName = "trit_trip_log")
public record TripLogSearchDoc(
    @JsonProperty("id") Long id,
    @JsonProperty("title") String title,
    @JsonProperty("content") String content,
    @JsonProperty("nickname") String nickname,
    @JsonProperty("profile_image_url") String profileImageUrl,
    @JsonProperty("image_url") String imageUrl,
    @JsonProperty("createdAt") LocalDateTime createdAt
) {}
