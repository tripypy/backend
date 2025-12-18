package com.ssafy.jjtrip.domain.user.dto;

import java.util.List;

public record AiAnalysisRequestDto(
    List<LogItem> logs
) {
    public record LogItem(
        String title,
        String content,
        String spotCategories
    ) {}
}
