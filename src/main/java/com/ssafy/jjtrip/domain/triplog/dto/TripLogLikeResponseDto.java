package com.ssafy.jjtrip.domain.triplog.dto;

public record TripLogLikeResponseDto(
    boolean liked,
    int likeCount
) {
}
