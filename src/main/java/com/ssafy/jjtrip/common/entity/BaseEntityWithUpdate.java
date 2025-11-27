package com.ssafy.jjtrip.common.entity;

import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public class BaseEntityWithUpdate extends BaseEntity {

	private LocalDateTime updatedAt;
}
