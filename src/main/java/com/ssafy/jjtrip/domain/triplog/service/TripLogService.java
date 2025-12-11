package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogImageResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogLikeResponseDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
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

    @Transactional
    public void addComment(Long logId, Long userId, TripLogCommentRequestDto commentRequestDto) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }

        TripLogComment comment = TripLogComment.builder()
                .logId(logId)
                .userId(userId)
                .content(commentRequestDto.content())
                .build();
        tripLogMapper.insertComment(comment);
        tripLogMapper.incrementCommentCount(logId);
    }

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
        tripLogMapper.incrementLikeCount(logId);
        int likeCount = tripLogMapper.getLikeCount(logId);
        return new TripLogLikeResponseDto(true, likeCount);
    }

    @Transactional
    public TripLogLikeResponseDto unlikeTripLog(Long logId, Long userId) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }
        tripLogMapper.deleteLike(logId, userId);
        tripLogMapper.decrementLikeCount(logId);
        int likeCount = tripLogMapper.getLikeCount(logId);
        return new TripLogLikeResponseDto(false, likeCount);
    }
}
