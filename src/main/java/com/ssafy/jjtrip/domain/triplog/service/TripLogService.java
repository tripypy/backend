package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.common.dto.PageDto;
import com.ssafy.jjtrip.common.dto.SliceDto;
import com.ssafy.jjtrip.common.util.RedisUtil;
import com.ssafy.jjtrip.domain.friend.dto.response.SimpleUserInfoDto;
import com.ssafy.jjtrip.domain.friend.service.FriendService;
import com.ssafy.jjtrip.domain.search.service.TripLogSearchService;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.service.TripService;
import com.ssafy.jjtrip.domain.triplog.dto.request.TripLogCreateRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.request.TripLogUpdateRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogCreateResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogFeedResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogImageResponseDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLog;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import com.ssafy.jjtrip.domain.user.service.UserValidateService;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@lombok.extern.slf4j.Slf4j
public class TripLogService {
    private final TripLogMapper tripLogMapper;
    private final UserValidateService userValidateService;
    private final TripService tripService;
    private final TripLogCommentService tripLogCommentService;
    private final TripLogLikeService tripLogLikeService;
    private final TripLogSearchService tripLogSearchService;
    private final FriendService friendService;
    private final RedisUtil redisUtil;

    private static final String TIMELINE_KEY_PREFIX = "timeline:";
    private static final int FRIEND_FEED_DAYS_THRESHOLD = 3;

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
        processAndSaveImages(tripLog.getId(), userId, requestDto.content());

        TripLog savedTripLog = tripLogMapper.findById(tripLog.getId())
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        Trip trip = tripService.findTripById(savedTripLog.getTripId());
        List<String> imageUrls = extractImageUrls(savedTripLog.getContent());
        tripLogSearchService.saveTripLog(savedTripLog, trip, imageUrls);

        if (savedTripLog.getVisibility() == TripLogVisibility.PUBLIC) {
            fanoutLogToFriendTimelines(userId, savedTripLog.getId(), savedTripLog.getCreatedAt());
        }

        return new TripLogCreateResponseDto(savedTripLog.getId());
    }

    public SliceDto<TripLogFeedResponseDto> getFriendTripLogFeed(Long userId, Long cursor, int limit, Long memberId) {
        String timelineKey = TIMELINE_KEY_PREFIX + userId;

        long nowMs = System.currentTimeMillis();
        long minScore = nowMs - Duration.ofDays(FRIEND_FEED_DAYS_THRESHOLD).toMillis();
        long maxScore = (cursor == null) ? Long.MAX_VALUE : cursor - 1;

        int queryLimit = limit + 1;

        Set<ZSetOperations.TypedTuple<String>> tuples =
                redisUtil.zrevrangeByScoreWithScores(timelineKey, minScore, maxScore, 0, queryLimit);

        if (tuples == null || tuples.isEmpty()) {
            return new SliceDto<>(Collections.emptyList(), null, false);
        }

        List<ZSetOperations.TypedTuple<String>> tupleList = new ArrayList<>(tuples);

        boolean hasNext = tupleList.size() > limit;
        if (hasNext) {
            tupleList = tupleList.subList(0, limit);
        }

        Long nextCursor = tupleList.isEmpty()
                ? null
                : tupleList.get(tupleList.size() - 1).getScore().longValue();

        List<Long> logIds = tupleList.stream()
                .map(t -> Long.valueOf(t.getValue()))
                .toList();

        List<TripLogFeedResponseDto.FeedData> tripLogsData = tripLogMapper.findLogsByIds(logIds, memberId);

        List<TripLogFeedResponseDto> tripLogs = mapToTripLogFeedResponse(tripLogsData);

        return new SliceDto<>(tripLogs, nextCursor, hasNext);
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

    public SliceDto<TripLogFeedResponseDto> getTripLogsBySpot(Long spotId, Long cursor, int limit, Long memberId) {
        final int queryLimit = limit + 1;
        List<TripLogFeedResponseDto.FeedData> tripLogsData = tripLogMapper.findTripLogsBySpotId(spotId, cursor, queryLimit, memberId);

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

    public TripLogDetailResponseDto getTripLogDetail(Long logId, Long memberId) {
        TripLogDetailResponseDto.BaseInfo baseInfo = tripLogMapper.findDetailById(logId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        if (baseInfo.visibility() == TripLogVisibility.PRIVATE) {
            if (memberId == null || !memberId.equals(baseInfo.authorId())) {
                throw new TripLogException(TripLogErrorCode.FORBIDDEN_ACCESS);
            }
        }

        List<TripLogImageResponseDto> images = tripLogMapper.findImagesByLogId(logId);
        List<TripLogCommentResponseDto> comments = tripLogCommentService.getCommentsByLogId(logId);

        int likeCount = tripLogLikeService.getLikeCount(logId);
        int commentCount = tripLogCommentService.getCommentCount(logId);

        return TripLogDetailResponseDto.from(baseInfo, images, comments, likeCount, commentCount);
    }

    private List<String> extractImageUrls(String content) {
        if (content == null || content.isBlank()) return Collections.emptyList();
        List<String> urls = new java.util.ArrayList<>();
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("!\\[.*?\\]\\((.*?)\\)");
        java.util.regex.Matcher matcher = pattern.matcher(content);
        while (matcher.find()) {
            urls.add(matcher.group(1));
        }
        return urls;
    }

    @Transactional
    public void updateTripLog(Long logId, Long userId, TripLogUpdateRequestDto requestDto) {
        validateLogAuthor(logId, userId);

        TripLog tripLog = TripLog.builder()
                .id(logId)
                .title(requestDto.title())
                .content(requestDto.content())
                .visibility(requestDto.visibility())
                .build();

        tripLogMapper.updateTripLog(tripLog);

        if (requestDto.content() != null) {
            tripLogMapper.deleteLogImages(logId);
            processAndSaveImages(logId, userId, requestDto.content());
        }

        TripLog updatedLog = tripLogMapper.findById(logId).orElseThrow();
        Trip trip = tripService.findTripById(updatedLog.getTripId());
        List<String> imageUrls = extractImageUrls(updatedLog.getContent());
        tripLogSearchService.saveTripLog(updatedLog, trip, imageUrls);
    }

    private void processAndSaveImages(Long logId, Long userId, String content) {
        if (content == null || content.isBlank()) {
            return;
        }

        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("!\\[.*?\\]\\((.*?)\\)");
        java.util.regex.Matcher matcher = pattern.matcher(content);

        int orderIndex = 0;
        while (matcher.find()) {
            String imageUrl = matcher.group(1);
            String imageRefKey = "img_" + orderIndex;

            tripLogMapper.insertTripLogImage(new TripLogMapper.LogImageInsertInfo(
                    logId, userId, imageUrl, orderIndex++, imageRefKey
            ));
        }
    }

    @Transactional
    public void deleteTripLog(Long logId, Long userId) {
        validateLogAuthor(logId, userId);
        tripLogMapper.deleteTripLog(logId);
        tripLogSearchService.deleteTripLog(logId);
    }

    private void validateLogAuthor(Long logId, Long userId) {
        Long authorId = tripLogMapper.findAuthorIdByLogId(logId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        if (!authorId.equals(userId)) {
            throw new TripLogException(TripLogErrorCode.FORBIDDEN_ACCESS);
        }
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

    @Async
    public void fanoutLogToFriendTimelines(Long authorId, Long logId, LocalDateTime createdAt) {
        List<SimpleUserInfoDto> friends = friendService.getFriendList(authorId);
        double score = createdAt.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();

        for (SimpleUserInfoDto friend : friends) {
            String timelineKey = TIMELINE_KEY_PREFIX + friend.getUserId();
            redisUtil.zadd(timelineKey, String.valueOf(logId), score);
        }
    }
}
