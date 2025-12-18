package com.ssafy.jjtrip.domain.triplog.dto.response;

public record TripLogLikeResponseDto(
    boolean liked,
    int likeCount
) {
}
