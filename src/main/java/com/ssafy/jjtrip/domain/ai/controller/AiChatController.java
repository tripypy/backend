package com.ssafy.jjtrip.domain.ai.controller;

import com.ssafy.jjtrip.domain.ai.dto.AiChatRequestDto;
import com.ssafy.jjtrip.domain.ai.dto.AiChatResponseDto;
import com.ssafy.jjtrip.domain.ai.service.OpenAiChatService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ai")
@RequiredArgsConstructor
public class AiChatController {

    private final OpenAiChatService chatService;

    @PostMapping("/chat")
    public ResponseEntity<AiChatResponseDto> chat(@Valid @RequestBody AiChatRequestDto requestDto) {
        AiChatResponseDto response = chatService.chat(requestDto);
        return ResponseEntity.ok(response);
    }
}
