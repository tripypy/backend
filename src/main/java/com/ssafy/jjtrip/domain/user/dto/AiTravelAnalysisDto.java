package com.ssafy.jjtrip.domain.user.dto;

import java.util.List;

public record AiTravelAnalysisDto(
    List<String> keywords,
    String summary,
    Scores scores
) {
    public record Scores(
        int rest,
        int exploration,
        int activity,
        int gourmet
    ) {}
}
