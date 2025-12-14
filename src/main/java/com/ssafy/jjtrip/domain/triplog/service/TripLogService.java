package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.common.dto.SliceDto;
import com.ssafy.jjtrip.domain.triplog.dto.*;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripLogService {

    private final TripLogMapper tripLogMapper;

    public SliceDto<TripLogFeedResponseDto> getTripLogFeed(Long cursor, int limit, Long memberId) {
        final int queryLimit = limit + 1;
        List<TripLogFeedResponseDto.FeedData> tripLogsData = tripLogMapper.findTripLogFeed(cursor, queryLimit, memberId);

        boolean hasNext = tripLogsData.size() > limit;
        if (hasNext) {
            tripLogsData.remove(limit);
        }

        Long nextCursor = null;
        if (!tripLogsData.isEmpty()) {
            nextCursor = tripLogsData.get(tripLogsData.size() - 1).logId();
        }

        List<TripLogFeedResponseDto> tripLogs;
        if (tripLogsData.isEmpty()) {
            tripLogs = Collections.emptyList();
        } else {
            List<Long> logIds = tripLogsData.stream().map(TripLogFeedResponseDto.FeedData::logId).toList();
            List<TripLogMapper.ImageInfo> images = tripLogMapper.findImagesByLogIds(logIds);

            Map<Long, List<TripLogImageResponseDto>> imagesByLogId = images.stream()
                    .collect(Collectors.groupingBy(
                            TripLogMapper.ImageInfo::logId,
                            Collectors.mapping(
                                    imageInfo -> new TripLogImageResponseDto(imageInfo.imageRefKey(), imageInfo.imageUrl(), imageInfo.orderIndex()),
                                    Collectors.toList()
                            )
                    ));

            tripLogs = tripLogsData.stream()
                    .map(data -> TripLogFeedResponseDto.from(data, imagesByLogId.getOrDefault(data.logId(), Collections.emptyList())))
                    .toList();
        }

        return new SliceDto<>(tripLogs, nextCursor, hasNext);
    }

    public TripLogDetailResponseDto getTripLogDetail(Long logId) {
        TripLogDetailResponseDto.BaseInfo baseInfo = tripLogMapper.findDetailById(logId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        List<TripLogImageResponseDto> images = tripLogMapper.findImagesByLogId(logId);
        List<TripLogCommentResponseDto> comments = tripLogMapper.findCommentsByLogId(logId);

        int likeCount = tripLogMapper.getLikeCount(logId);
        int commentCount = tripLogMapper.getCommentCount(logId);

        return TripLogDetailResponseDto.from(baseInfo, images, comments, likeCount, commentCount);
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
}
