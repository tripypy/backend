package com.ssafy.jjtrip.common.entity;

import java.time.LocalDateTime;

import lombok.Getter;

@Getter
public class BaseEntityWithUpdate extends BaseEntity {

	private LocalDateTime updatedAt;
}
