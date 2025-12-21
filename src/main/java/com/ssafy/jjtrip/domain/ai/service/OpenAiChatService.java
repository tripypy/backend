package com.ssafy.jjtrip.domain.ai.service;

import com.ssafy.jjtrip.common.openai.OpenAiClient;
import com.ssafy.jjtrip.domain.ai.dto.AiChatRequestDto;
import com.ssafy.jjtrip.domain.ai.dto.AiChatResponseDto;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class OpenAiChatService {

    private final OpenAiClient openAiClient;

    public AiChatResponseDto chat(AiChatRequestDto request) {
        List<Map<String, Object>> messages = request.messages().stream()
                .map(msg -> Map.of(
                        "role", (Object) msg.role(),
                        "content", (Object) msg.content()
                ))
                .collect(Collectors.toList());

        String responseText = openAiClient.chatCompletion(messages);
        return new AiChatResponseDto(responseText);
    }
}
