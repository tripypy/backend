package com.ssafy.jjtrip.domain.triplog.dto;

import jakarta.validation.constraints.NotBlank;

public record ImageUploadRequestDto(
        @NotBlank(message = "파일명은 필수 입력값입니다.")
        String fileName
) {
}
