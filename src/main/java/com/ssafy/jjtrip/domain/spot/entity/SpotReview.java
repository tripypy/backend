package com.ssafy.jjtrip.domain.spot.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import java.math.BigDecimal;
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
public class SpotReview extends BaseEntityWithUpdate {
    private Long spotId;
    private Long userId;
    private BigDecimal rating;
    private String content;
}
