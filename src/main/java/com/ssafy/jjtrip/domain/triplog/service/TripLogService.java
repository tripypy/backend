package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.common.dto.PageDto;
import com.ssafy.jjtrip.common.dto.SliceDto;
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
@lombok.extern.slf4j.Slf4j
public class TripLogService {
    private final TripLogMapper tripLogMapper;
    private final UserValidateService userValidateService;
    private final TripService tripService;
    private final TripLogCommentService tripLogCommentService;
    private final TripLogLikeService tripLogLikeService;
    private final TripLogSearchService tripLogSearchService;

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

        // Sync ES
        Trip trip = tripService.getTripDetail(requestDto.tripId(), userId);
        List<String> imageUrls = extractImageUrls(tripLog.getContent());
        tripLogSearchService.saveTripLog(tripLog, trip, imageUrls);

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
    
    // Private helper for extracting URLs to avoid duplicating regex logic
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
        
        // Sync ES
        // Need full TripLog and Trip data
        TripLog updatedLog = tripLogMapper.findById(logId).orElseThrow(); 
        Trip trip = tripService.getTripDetail(updatedLog.getTripId(), userId);
        List<String> imageUrls = extractImageUrls(updatedLog.getContent());
        tripLogSearchService.saveTripLog(updatedLog, trip, imageUrls);
    }

    private void processAndSaveImages(Long logId, Long userId, String content) {
        if (content == null || content.isBlank()) {
            return;
        }

        // Markdown Image Pattern: ![alt](url)
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
}
