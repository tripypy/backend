package com.ssafy.jjtrip.domain.triplog.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class TripLog extends BaseEntityWithUpdate {

    private Long tripId;
    private String title;
    private String content;
    private String locationSummary;
    private Integer likeCount;
    private Integer commentCount;

    private Trip trip;
    private List<TripLogImage> images;
    private List<TripLogComment> comments;
}
