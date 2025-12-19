package com.ssafy.jjtrip.domain.search.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.DateFormat;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

import java.util.List;

@Document(indexName = "trit_trip")
public record TripSearchDoc(
    @Id
    @Field(name = "trip_id")
    @JsonProperty("trip_id") Long tripId,

    @Field(name = "user_id")
    @JsonProperty("user_id") Long userId,

    @Field(name = "title")
    @JsonProperty("title") String title,

    @Field(name = "location_summary")
    @JsonProperty("location_summary") String locationSummary,

    @Field(name = "start_date", type = FieldType.Keyword)
    @JsonProperty("start_date") String startDate,

    @Field(name = "end_date", type = FieldType.Keyword)
    @JsonProperty("end_date") String endDate,

    @Field(name = "created_at", type = FieldType.Keyword)
    @JsonProperty("created_at") String createdAt,

    @Field(name = "spot_names")
    @JsonProperty("spot_names") List<String> spotNames,

    @Field(name = "spot_categories")
    @JsonProperty("spot_categories") List<String> spotCategories,

    @Field(name = "spots_preview")
    @JsonProperty("spots_preview") List<SpotPreview> spotsPreview
) {
    public record SpotPreview(
        @Field(name = "spot_id")
        @JsonProperty("spot_id") Long spotId,

        @Field(name = "name")
        @JsonProperty("name") String name,

        @Field(name = "category")
        @JsonProperty("category") String category
    ) {}
}
