package com.ssafy.jjtrip.domain.user.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class UserProfile extends BaseEntityWithUpdate {

    private Long userId; // FK to User
    private String bio;
    private String intro;
    private Long homeRegionId; // FK to Region
    private String travelStyleSummary;
    private Long travelStyleId; // FK to TravelStyle
    private String profileBannerUrl;
    private Boolean isProfilePublic;
}
