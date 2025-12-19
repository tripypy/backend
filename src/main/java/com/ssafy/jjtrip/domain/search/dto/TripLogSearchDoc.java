package com.ssafy.jjtrip.domain.search.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Document(indexName = "trit_trip_log")
public record TripLogSearchDoc(
    @Field(name = "log_id")
    @JsonProperty("log_id") Long logId,

    @Field(name = "trip_id")
    @JsonProperty("trip_id") Long tripId,

    @Field(name = "user_id")
    @JsonProperty("user_id") Long userId,

    @Field(name = "title")
    @JsonProperty("title") String title,

    @Field(name = "content")
    @JsonProperty("content") String content,

    @Field(name = "trip_location_summary")
    @JsonProperty("trip_location_summary") String tripLocationSummary,

    @Field(name = "trip_start_date")
    @JsonProperty("trip_start_date") LocalDate tripStartDate,

    @Field(name = "trip_end_date")
    @JsonProperty("trip_end_date") LocalDate tripEndDate,

    @Field(name = "created_at")
    @JsonProperty("created_at") LocalDateTime createdAt,

    @Field(name = "image_urls")
    @JsonProperty("image_urls") List<String> imageUrls
) {}
