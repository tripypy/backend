package com.ssafy.jjtrip.domain.user.dto.response;

import com.ssafy.jjtrip.domain.trip.dto.TripDetailResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogSummaryDto;
import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PublicUserProfileResponseDto {
    private Long id;
    private String nickname;
    private String profileImageUrl;
    private String bio;
    private String intro;
    private Long homeRegionId;
    private String travelStyleSummary;
    private Long travelStyleId;
    private String profileBannerUrl;
    private Boolean isProfilePublic;
    private int friendsCount;

    private List<TripResponseDto> tripOverviews;
    private List<TripDetailResponseDto> completedTripDetails;
    private List<TripLogSummaryDto> logs;
}
