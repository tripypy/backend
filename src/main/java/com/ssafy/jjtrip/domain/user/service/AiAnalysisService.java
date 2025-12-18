package com.ssafy.jjtrip.domain.user.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.CommonErrorCode;
import com.ssafy.jjtrip.common.openai.OpenAiClient;
import com.ssafy.jjtrip.domain.triplog.service.TripLogQueryService;
import com.ssafy.jjtrip.domain.user.dto.AiAnalysisRequestDto;
import com.ssafy.jjtrip.domain.user.dto.AiTravelAnalysisDto;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AiAnalysisService {

    private final TripLogQueryService tripLogQueryService;
    private final UserService userService;
    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper; // Response Parsing용으로 유지

    private static final String SYSTEM_PROMPT = """
            You are a travel analyst AI. Analyze the given travel logs and return a JSON.
            
            [Requirements]
            1. 'keywords': 3 hashtags in **Korean** (e.g., "#힐링_가득", "#골목_탐험").
            2. 'summary': Describe the **user's travel style** in one warm, insightful sentence in Korean. Use polite formal style ('~입니다'). **DO NOT use subject honorifics (주체 높임) such as '~이십니다' or '~하십니다'.** You MUST end the sentence with " 타입입니다." (e.g., "조용한 골목과 여유를 즐기는 힐링 타입입니다.")
            3. 'scores': Integer 0-100 for 'rest', 'exploration', 'activity', 'gourmet'.
            
            [JSON Format]
            {
              "keywords": ["#TAG1", ...],
              "summary": "...",
              "scores": { "rest": 0, "exploration": 0, "activity": 0, "gourmet": 0 }
            }
            RETURN ONLY RAW JSON.
            """;

    @Transactional
    public AiTravelAnalysisDto analyzeUserTravelStyle(Long userId) {
        log.info("사용자 여행 성향 분석 시작. 사용자 ID: {}", userId);

        // 1. 여행 로그 데이터 조회
        List<AiAnalysisRequestDto.LogItem> logs = tripLogQueryService.getLogsForAnalysis(userId);
        if (logs.isEmpty()) {
            throw new BusinessException(CommonErrorCode.RESOURCE_NOT_FOUND); 
        }

        // 2. AI에게 보낼 프롬프트 구성
        String userPrompt = buildPrompt(logs);

        // 3. AI API 호출
        String jsonResponse = openAiClient.chatCompletion(SYSTEM_PROMPT, userPrompt);

        // 4. 결과 파싱 및 DB 저장
        try {
            AiTravelAnalysisDto result = objectMapper.readValue(jsonResponse, AiTravelAnalysisDto.class);
            
            // 분석 결과를 유저 프로필에 업데이트 (JSON 문자열 그대로 저장)
            userService.updateTravelStyle(userId, jsonResponse);
            
            log.info("사용자 여행 성향 분석 완료. 사용자 ID: {}", userId);
            return result;
        } catch (JsonProcessingException e) {
            log.error("AI 응답 JSON 파싱 실패", e);
            throw new BusinessException(CommonErrorCode.INTERNAL_SERVER_ERROR);
        }
    }

    private String buildPrompt(List<AiAnalysisRequestDto.LogItem> logs) {
        StringBuilder sb = new StringBuilder();
        sb.append("Here are the user's recent travel logs:\n\n");
        
        for (AiAnalysisRequestDto.LogItem log : logs) {
            sb.append(String.format("- Title: %s\n", log.title()));
            sb.append(String.format("  Content: %s\n", log.content()));
            if (log.spotCategories() != null && !log.spotCategories().isEmpty()) {
                sb.append(String.format("  Visited Spots Categories: %s\n", String.join(", ", log.spotCategories())));
            }
            sb.append("\n");
        }
        
        sb.append("Analyze these logs and provide the result.");
        return sb.toString();
    }
}
