package com.ssafy.jjtrip.domain.triplog.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TripLogSummaryDto {
    private Long logId;
    private Long tripId;
    private String title;
    private String thumbnailUrl;
}
