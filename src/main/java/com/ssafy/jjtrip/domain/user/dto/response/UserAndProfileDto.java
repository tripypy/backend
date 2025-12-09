package com.ssafy.jjtrip.domain.user.dto.response;

import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UserAndProfileDto {
    // From User entity
    private Long id;
    private Role role;
    private UserStatus status;
    private String email;
    private String nickname;
    private String profileImageUrl;

    // From UserProfile entity
    private String bio;
    private String intro;
    private Long homeRegionId;
    private String travelStyleSummary;
    private Long travelStyleId;
    private String profileBannerUrl;
    private Boolean isProfilePublic;
}
