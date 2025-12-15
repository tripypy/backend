package com.ssafy.jjtrip.domain.search.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.elasticsearch.annotations.Document;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Document(indexName = "trit_trip")
public record TripSearchDoc(
    @JsonProperty("id") Long id,
    @JsonProperty("title") String title,
    @JsonProperty("nickname") String nickname,
    @JsonProperty("profile_image_url") String profileImageUrl,
    @JsonProperty("image_url") String imageUrl,
    @JsonProperty("start_date") LocalDate startDate,
    @JsonProperty("end_date") LocalDate endDate,
    @JsonProperty("createdAt") LocalDateTime createdAt
) {}