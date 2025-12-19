package com.ssafy.jjtrip.domain.friend.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class FriendRequest extends BaseEntityWithUpdate {
    private Long requesterId;
    private Long receiverId;
}