package com.ssafy.jjtrip.domain.ai.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record AiChatRequestDto(

    @Valid
    @NotNull(message = "메시지 리스트는 필수입니다.")
    List<ChatMessageDto> messages
) {
    public record ChatMessageDto(

        @NotBlank(message = "Role 값은 필수입니다.")
        String role, // "system", "user", "assistant"

        @NotBlank(message = "Content 값은 필수입니다.")
        String content
    ) {}
}
