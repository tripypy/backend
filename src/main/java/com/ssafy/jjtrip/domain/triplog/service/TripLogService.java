package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogImageResponseDto;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripLogService {

    private final TripLogMapper tripLogMapper;

    public TripLogDetailResponseDto getTripLogDetail(Long logId) {
        TripLogDetailResponseDto.BaseInfo baseInfo = tripLogMapper.findDetailById(logId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        List<TripLogImageResponseDto> images = tripLogMapper.findImagesByLogId(logId);

        List<TripLogCommentResponseDto> comments = tripLogMapper.findCommentsByLogId(logId);

        return TripLogDetailResponseDto.from(baseInfo, images, comments);
    }
}
