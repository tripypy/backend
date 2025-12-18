package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogLikeResponseDto;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripLogLikeService {

    private final TripLogMapper tripLogMapper;

    public TripLogLikeResponseDto getLikeStatus(Long logId, Long userId) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }
        boolean liked = tripLogMapper.hasUserLiked(logId, userId);
        int likeCount = tripLogMapper.getLikeCount(logId);
        return new TripLogLikeResponseDto(liked, likeCount);
    }

    @Transactional
    public TripLogLikeResponseDto likeTripLog(Long logId, Long userId) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }
        tripLogMapper.insertLike(logId, userId);
        int likeCount = tripLogMapper.getLikeCount(logId);
        return new TripLogLikeResponseDto(true, likeCount);
    }

    @Transactional
    public TripLogLikeResponseDto unlikeTripLog(Long logId, Long userId) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }
        tripLogMapper.deleteLike(logId, userId);
        int likeCount = tripLogMapper.getLikeCount(logId);
        return new TripLogLikeResponseDto(false, likeCount);
    }

    public int getLikeCount(Long logId) {
        return tripLogMapper.getLikeCount(logId);
    }
}
