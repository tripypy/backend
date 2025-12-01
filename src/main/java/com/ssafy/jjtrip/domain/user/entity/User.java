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
public class User extends BaseEntityWithUpdate {

    private Role role;
    private UserStatus status;
    private String email;
    private String passwordHash;
    private String nickname;
    private String profileImageUrl;
}
