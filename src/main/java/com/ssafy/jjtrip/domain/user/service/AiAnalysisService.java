package com.ssafy.jjtrip.domain.user.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import com.ssafy.jjtrip.domain.user.dto.AiAnalysisRequestDto;
import com.ssafy.jjtrip.domain.user.dto.AiTravelAnalysisDto;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.CommonErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class AiAnalysisService {

    private final TripLogMapper tripLogMapper;
    private final UserMapper userMapper;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    
    @Value("${openai.api.key}")
    private String openAiApiKey;

    @Value("${openai.model:gpt-4.1-mini}")
    private String openAiModel;

    // SSAFY GMS 전용 엔드포인트
    private static final String OPENAI_API_URL = "https://gms.ssafy.io/gmsapi/api.openai.com/v1/chat/completions";

    @Transactional
    public AiTravelAnalysisDto analyzeUserTravelStyle(Long userId) {
        log.info("사용자 여행 성향 분석 시작. 사용자 ID: {}", userId);

        // 1. 여행 로그 데이터 조회
        List<AiAnalysisRequestDto.LogItem> logs = tripLogMapper.findLogsForAnalysis(userId);
        if (logs.isEmpty()) {
            throw new BusinessException(CommonErrorCode.RESOURCE_NOT_FOUND); 
        }

        // 2. AI에게 보낼 프롬프트 구성
        String prompt = buildPrompt(logs);

        // 3. AI API 호출
        String jsonResponse = callOpenAiApi(prompt);

        // 4. 결과 파싱 및 DB 저장
        try {
            AiTravelAnalysisDto result = objectMapper.readValue(jsonResponse, AiTravelAnalysisDto.class);
            
            // 분석 결과를 유저 프로필에 업데이트 (JSON 문자열 그대로 저장)
            userMapper.updateTravelStyleSummary(userId, jsonResponse);
            
            log.info("사용자 여행 성향 분석 완료. 사용자 ID: {}", userId);
            return result;
        } catch (JsonProcessingException e) {
            log.error("AI 응답 JSON 파싱 실패", e);
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        }
    }

    private String buildPrompt(List<AiAnalysisRequestDto.LogItem> logs) {
        StringBuilder sb = new StringBuilder();
        sb.append("User logs:\n");
        for (AiAnalysisRequestDto.LogItem item : logs) {
            sb.append("- Title: ").append(item.title()).append("\n");
            sb.append("  Content: ").append(item.content()).append("\n");
            sb.append("  Categories: ").append(item.spotCategories()).append("\n\n");
        }
        return sb.toString();
    }

    private String callOpenAiApi(String userPrompt) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(openAiApiKey);
        // Cloudflare 차단 방지를 위한 User-Agent 설정
        headers.set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        // 시스템 프롬프트 (AI 역할 및 응답 규격 정의)
        Map<String, Object> messageSystem = new HashMap<>();
        messageSystem.put("role", "system");
        messageSystem.put("content", """
            You are a travel analyst AI. Analyze the given travel logs and return a JSON.
            
            [Requirements]
            1. 'keywords': 3 hashtags (e.g., "#CHILL_VIBE").
            2. 'summary': One warm, insightful sentence in Korean (honorific/polite).
            3. 'scores': Integer 0-100 for 'rest', 'exploration', 'activity', 'gourmet'.
            
            [JSON Format]
            {
              "keywords": ["#TAG1", ...],
              "summary": "...",
              "scores": { "rest": 0, "exploration": 0, "activity": 0, "gourmet": 0 }
            }
            RETURN ONLY RAW JSON.
            """);

        // 유저 프롬프트 (실제 여행 데이터 삽입)
        Map<String, Object> messageUser = new HashMap<>();
        messageUser.put("role", "user");
        messageUser.put("content", userPrompt);

        // 요청 바디 생성
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("model", openAiModel);
        requestBody.put("messages", List.of(messageSystem, messageUser));
        requestBody.put("max_tokens", 2048); // 예시와 유사하게 설정
        requestBody.put("temperature", 0.5); // 창의성 조절
        // requestBody.put("response_format", Map.of("type", "json_object")); // GMS/Cloudflare 호환성 문제로 제거 (프롬프트로 제어)

        try {
            String requestJson = objectMapper.writeValueAsString(requestBody);
            log.debug("AI 요청 Payload: {}", requestJson);

            HttpEntity<String> entity = new HttpEntity<>(requestJson, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(OPENAI_API_URL, entity, String.class);
            
            JsonNode root = objectMapper.readTree(response.getBody());
            return root.path("choices").get(0).path("message").path("content").asText();
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("AI API HTTP 오류: Status={}, Body={}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            log.error("OpenAI API 호출 중 알 수 없는 오류 발생", e);
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        }
    }
}
