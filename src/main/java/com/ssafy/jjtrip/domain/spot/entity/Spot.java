package com.ssafy.jjtrip.domain.spot.entity;

import com.ssafy.jjtrip.common.entity.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.math.BigDecimal;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class Spot extends BaseEntity {

    private String kakaoPlaceId;
    private String name;
    private String address;
    private String category;
    private BigDecimal lat;
    private BigDecimal lng;
    private String placeUrl;
    private String thumbnailUrl;
    private Integer reviewCount;
    private BigDecimal averageRating;
}
