package com.ssafy.jjtrip.domain.user.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class PublicUserProfileResponseDto {
    private Long id;
    // No email
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

    public static PublicUserProfileResponseDto from(UserAndProfileDto userAndProfile) {
        return PublicUserProfileResponseDto.builder()
                .id(userAndProfile.getId())
                .nickname(userAndProfile.getNickname())
                .profileImageUrl(userAndProfile.getProfileImageUrl())
                .bio(userAndProfile.getBio())
                .intro(userAndProfile.getIntro())
                .homeRegionId(userAndProfile.getHomeRegionId())
                .travelStyleSummary(userAndProfile.getTravelStyleSummary())
                .travelStyleId(userAndProfile.getTravelStyleId())
                .profileBannerUrl(userAndProfile.getProfileBannerUrl())
                .isProfilePublic(userAndProfile.getIsProfilePublic())
                .friendsCount(userAndProfile.getFriendsCount())
                .build();
    }
}
