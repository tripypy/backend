package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.common.dto.PageDto;
import com.ssafy.jjtrip.common.dto.SliceDto;
import com.ssafy.jjtrip.domain.trip.service.TripService;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCreateRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCreateResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogFeedResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogImageResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogLikeResponseDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLog;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import com.ssafy.jjtrip.domain.user.service.UserValidateService;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripLogService {
    private final TripLogMapper tripLogMapper;
    private final UserValidateService userValidateService;
    private final TripService tripService;

    @Transactional
    public TripLogCreateResponseDto createTripLog(Long userId, TripLogCreateRequestDto requestDto) {
        tripService.validateTripExists(requestDto.tripId());

        if (tripLogMapper.existsByTripId(requestDto.tripId())) {
            throw new TripLogException(TripLogErrorCode.TRIPLOG_ALREADY_EXISTS);
        }

        TripLogVisibility visibility = requestDto.visibility() == null ? TripLogVisibility.PUBLIC : requestDto.visibility();

        TripLog tripLog = TripLog.builder()
                .tripId(requestDto.tripId())
                .title(requestDto.title())
                .content(requestDto.content())
                .visibility(visibility)
                .build();

        tripLogMapper.insertTripLog(tripLog);
        return new TripLogCreateResponseDto(tripLog.getId());
    }

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

        List<TripLogFeedResponseDto> tripLogs = mapToTripLogFeedResponse(tripLogsData);

        return new SliceDto<>(tripLogs, nextCursor, hasNext);
    }

    public PageDto<TripLogFeedResponseDto> getUserTripLogs(Long authorId, int page, int size, Long memberId) {
        userValidateService.validateUserExists(authorId);

        int offset = (page - 1) * size;
        List<TripLogFeedResponseDto.FeedData> tripLogsData = tripLogMapper.findTripLogsByUserId(offset, size, memberId, authorId);
        long totalElements = tripLogMapper.countTripLogsByUserId(memberId, authorId);
        int totalPages = (int) Math.ceil((double) totalElements / size);

        List<TripLogFeedResponseDto> tripLogs = mapToTripLogFeedResponse(tripLogsData);

        return new PageDto<>(tripLogs, page, size, totalElements, totalPages);
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

    private List<TripLogFeedResponseDto> mapToTripLogFeedResponse(List<TripLogFeedResponseDto.FeedData> tripLogsData) {
        if (tripLogsData.isEmpty()) {
            return Collections.emptyList();
        }

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

        return tripLogsData.stream()
                .map(data -> TripLogFeedResponseDto.from(data, imagesByLogId.getOrDefault(data.logId(), Collections.emptyList())))
                .toList();
    }
}
