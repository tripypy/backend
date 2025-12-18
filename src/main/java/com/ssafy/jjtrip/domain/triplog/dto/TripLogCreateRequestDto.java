package com.ssafy.jjtrip.domain.triplog.dto;

import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record TripLogCreateRequestDto(

        @NotNull(message = "여행 ID는 필수입니다.")
        Long tripId,

        @NotBlank(message = "제목은 필수입니다.")
        @Size(max = 255, message = "제목은 255자를 초과할 수 없습니다.")
        String title,

        @NotBlank(message = "내용은 필수입니다.")
        String content,

        TripLogVisibility visibility
) {
}
