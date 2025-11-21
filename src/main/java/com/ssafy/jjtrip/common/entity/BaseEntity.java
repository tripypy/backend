package com.ssafy.jjtrip.common.entity;

import java.time.LocalDateTime;

import lombok.Getter;

@Getter
public abstract class BaseEntity {

    private Long id;
    private LocalDateTime createdAt;
}
