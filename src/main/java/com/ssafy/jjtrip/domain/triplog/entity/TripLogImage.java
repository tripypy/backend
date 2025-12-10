package com.ssafy.jjtrip.domain.triplog.entity;

import com.ssafy.jjtrip.common.entity.BaseEntity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class TripLogImage extends BaseEntity {

    private Long logId;
    private Long userId;
    private String imageUrl;
    private Integer orderIndex;
    private String imageRefKey;
}
