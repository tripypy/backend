package com.ssafy.jjtrip.domain.triplog.dto.response;

public record TripLogImageResponseDto(
        String imageRefKey,
        String imageUrl,
        int orderIndex
) {
}
