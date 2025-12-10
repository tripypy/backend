package com.ssafy.jjtrip.domain.triplog.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import com.ssafy.jjtrip.domain.user.entity.User;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class TripLogComment extends BaseEntityWithUpdate {

    private Long logId;
    private Long userId;
    private String content;

    private User user;
}
