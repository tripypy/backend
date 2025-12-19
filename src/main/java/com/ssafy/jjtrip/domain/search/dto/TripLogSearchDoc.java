package com.ssafy.jjtrip.domain.search.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.DateFormat;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;


import java.util.List;

@Document(indexName = "trit_trip_log")
public record TripLogSearchDoc(
    @Id
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

    @Field(name = "trip_start_date", type = FieldType.Keyword)
    @JsonProperty("trip_start_date") String tripStartDate,

    @Field(name = "trip_end_date", type = FieldType.Keyword)
    @JsonProperty("trip_end_date") String tripEndDate,

    @Field(name = "created_at", type = FieldType.Keyword)
    @JsonProperty("created_at") String createdAt,

    @Field(name = "image_urls")
    @JsonProperty("image_urls") List<String> imageUrls
) {}
