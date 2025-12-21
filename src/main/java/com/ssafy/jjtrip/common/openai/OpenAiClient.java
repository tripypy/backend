package com.ssafy.jjtrip.common.openai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.CommonErrorCode;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Component
@RequiredArgsConstructor
public class OpenAiClient {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${openai.api.url}")
    private String openAiApiUrl;

    @Value("${openai.api.key}")
    private String openAiApiKey;

    @Value("${openai.model}")
    private String openAiModel;

    public String chatCompletion(String systemPrompt, String userPrompt) {
        Map<String, Object> messageSystem = new HashMap<>();
        messageSystem.put("role", "system");
        messageSystem.put("content", systemPrompt);

        Map<String, Object> messageUser = new HashMap<>();
        messageUser.put("role", "user");
        messageUser.put("content", userPrompt);

        return chatCompletion(List.of(messageSystem, messageUser));
    }

    public String chatCompletion(List<Map<String, Object>> messages) {
        log.debug("OpenAI API 호출 [Model: {}] Messages count: {}", openAiModel, messages.size());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(openAiApiKey);
        headers.set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("model", openAiModel);
        requestBody.put("messages", messages);
        requestBody.put("max_tokens", 2048);
        requestBody.put("temperature", 0.7); // Slightly higher for chat creativity

        try {
            String requestJson = objectMapper.writeValueAsString(requestBody);
            // log.debug("AI 요청 Payload: {}", requestJson); // Payload can be large with history

            HttpEntity<String> entity = new HttpEntity<>(requestJson, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(openAiApiUrl, entity, String.class);

            JsonNode root = objectMapper.readTree(response.getBody());
            return root.path("choices").get(0).path("message").path("content").asText();
        } catch (HttpClientErrorException e) {
            log.error("AI API HTTP 오류: Status={}, Body={}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        } catch (JsonProcessingException e) {
            log.error("JSON 처리 오류", e);
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            log.error("OpenAI API 호출 중 알 수 없는 오류 발생", e);
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        }
    }
}
