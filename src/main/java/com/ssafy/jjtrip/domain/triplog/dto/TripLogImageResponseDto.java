package com.ssafy.jjtrip.domain.triplog.dto;

public record TripLogImageResponseDto(
        String imageRefKey,
        String imageUrl,
        int orderIndex
) {
}
