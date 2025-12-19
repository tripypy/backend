package com.ssafy.jjtrip.domain.friend.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Friendship {
    private Long userIdA;
    private Long userIdB;
    private LocalDateTime createdAt;
}
