package com.ssafy.jjtrip.common.s3.dto;

public record PresignedUrlResponseDto(
        String presignedUrl,
        String url,
        String key
) {
}
