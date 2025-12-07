package com.ssafy.jjtrip.domain.trip.entity;

import com.ssafy.jjtrip.common.entity.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class TripItem extends BaseEntity {

    private Long tripId;
    private Long spotId;
    private int dayNumber;
    private int orderIndex;
    private String memo;
}
