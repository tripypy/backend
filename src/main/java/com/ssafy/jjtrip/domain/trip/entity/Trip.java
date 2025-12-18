package com.ssafy.jjtrip.domain.trip.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class Trip extends BaseEntityWithUpdate {

    private Long userId;
    private String title;
    private LocalDate startDate;
    private LocalDate endDate;
    private TripStatus status;
    private TripVisibility visibility;
    private String locationSummary;

    // 상세 조회 시 JOIN 결과를 담기 위한 필드
    @Builder.Default
    private List<TripItem> tripItems = new ArrayList<>();

    public static Trip createScrap(Trip source, Long userId) {
        return Trip.builder()
                .userId(userId)
                .title("스크랩: " + source.getTitle())
                .startDate(source.getStartDate())
                .endDate(source.getEndDate())
                .status(TripStatus.PLANNED)
                .visibility(TripVisibility.PRIVATE)
                .build();
    }
}
