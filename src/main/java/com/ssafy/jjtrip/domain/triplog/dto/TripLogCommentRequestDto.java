package com.ssafy.jjtrip.domain.triplog.dto;

import jakarta.validation.constraints.NotBlank;

public record TripLogCommentRequestDto(
    @NotBlank(message = "댓글 내용은 필수 입력값입니다.")
    String content,
    Long parentId
) {
}
