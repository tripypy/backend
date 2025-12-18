package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import com.ssafy.jjtrip.domain.user.dto.AiAnalysisRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripLogQueryService {

    private final TripLogMapper tripLogMapper;

    public List<AiAnalysisRequestDto.LogItem> getLogsForAnalysis(Long userId) {
        return tripLogMapper.findLogsForAnalysis(userId);
    }
}
