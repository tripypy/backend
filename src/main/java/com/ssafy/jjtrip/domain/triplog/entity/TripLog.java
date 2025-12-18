package com.ssafy.jjtrip.domain.triplog.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class TripLog extends BaseEntityWithUpdate {

    private Long tripId;
    private String title;
    private String content;
    private TripLogVisibility visibility;

    private Trip trip;
    private List<TripLogImage> images;
    private List<TripLogComment> comments;
}
