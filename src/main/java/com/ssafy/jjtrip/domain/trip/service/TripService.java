package com.ssafy.jjtrip.domain.trip.service;

import com.ssafy.jjtrip.domain.notification.entity.NotificationType;
import com.ssafy.jjtrip.domain.notification.service.NotificationService;
import com.ssafy.jjtrip.domain.search.service.TripLogSearchService;
import com.ssafy.jjtrip.domain.search.service.TripSearchService;
import com.ssafy.jjtrip.domain.spot.service.SpotService;
import com.ssafy.jjtrip.domain.trip.dto.TripDetailResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripItemsReplaceRequestDto;
import com.ssafy.jjtrip.domain.trip.dto.TripResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripUpdateRequestDto;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;
import com.ssafy.jjtrip.domain.trip.exception.TripErrorCode;
import com.ssafy.jjtrip.domain.trip.exception.TripException;
import com.ssafy.jjtrip.domain.trip.mapper.TripMapper;
import com.ssafy.jjtrip.domain.triplog.entity.TripLog;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import java.util.Collections;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripService {

    private final TripMapper tripMapper;
    private final SpotService spotService;
    private final LocationSummaryService locationSummaryService;
    private final TripSearchService tripSearchService;
    private final TripLogMapper tripLogMapper;
    private final TripLogSearchService tripLogSearchService;
    private final NotificationService notificationService;

    @Transactional
    public Trip createTrip(Long userId) {
        Trip newTrip = Trip.builder()
                .userId(userId)
                .title("임시 여행") // 기본 제목
                .status(TripStatus.DRAFT) // 기본 상태
                .visibility(TripVisibility.PRIVATE) // 기본 공개 여부
                .build();
        tripMapper.insert(newTrip);
        newTrip.setTripItems(new java.util.ArrayList<>()); // Initialize tripItems to prevent NPE
        
        // ES Sync (Private by default, but ensuring sync logic)
        tripSearchService.saveTrip(newTrip, newTrip.getTripItems());
        
        return newTrip;
    }

    public List<TripResponseDto> findMyTrips(Long userId, TripStatus status) {
        List<Trip> trips;
        if (status == null) {
            trips = tripMapper.selectByUserId(userId);
        } else {
            trips = tripMapper.selectByUserIdAndStatus(userId, status);
        }

        return trips.stream()
                 .map(trip -> convertToTripResponseDto(trip, userId))
                 .toList();
    }

    private TripResponseDto convertToTripResponseDto(Trip trip, Long userId) {
        boolean isOwner = trip.getUserId().equals(userId);
        int spots = tripMapper.countTripItemsByTripId(trip.getId());
        List<String> spotPreviewNames = tripMapper.selectSpotPreviewNamesByTripId(trip.getId());
        List<TripResponseDto.SpotPreviewDto> spotPreviews = spotPreviewNames.stream()
                .map(TripResponseDto.SpotPreviewDto::new)
                .toList();
        // Tags are not implemented yet, so return an empty list
        List<String> tags = List.of();

        Long logId = tripLogMapper.findByTripId(trip.getId()).stream()
                .findFirst()
                .map(TripLog::getId)
                .orElse(null);

        return TripResponseDto.from(trip, isOwner, spots, tags, spotPreviews, logId);
    }

    public TripDetailResponseDto getTripDetail(Long tripId, Long userId) {
        Trip trip = findTripById(tripId);

        if (trip.getVisibility() != TripVisibility.PUBLIC && (userId == null || !trip.getUserId().equals(userId))) {
            throw new TripException(TripErrorCode.FORBIDDEN_TRIP_ACCESS);
        }

        List<TripItem> tripItems = tripMapper.selectItemsWithSpotsByTripId(tripId);
        trip.setTripItems(tripItems);

        Long logId = tripLogMapper.findByTripId(tripId).stream()
                .findFirst()
                .map(TripLog::getId)
                .orElse(null);

        return TripDetailResponseDto.from(trip, userId, logId);
    }

    @Transactional
    public void updateTrip(Long tripId, TripUpdateRequestDto requestDto, Long userId) {
        Trip trip = getTripForModification(tripId, userId);

        if (requestDto.title() != null) trip.setTitle(requestDto.title());
        if (requestDto.startDate() != null) trip.setStartDate(requestDto.startDate());
        if (requestDto.endDate() != null) trip.setEndDate(requestDto.endDate());
        if (requestDto.status() != null) trip.setStatus(requestDto.status());
        if (requestDto.visibility() != null) trip.setVisibility(requestDto.visibility());

        tripMapper.update(trip);
        
        List<TripItem> items = tripMapper.selectItemsWithSpotsByTripId(tripId);
        tripSearchService.saveTrip(trip, items);

        // Sync associated logs to ES (e.g., when visibility changes)
        List<TripLog> tripLogs = tripLogMapper.findByTripId(tripId);
        for (TripLog log : tripLogs) {
            List<String> imageUrls = extractImageUrls(log.getContent());
            tripLogSearchService.saveTripLog(log, trip, imageUrls);
        }
    }

    @Transactional
    public void deleteTrip(Long tripId, Long userId) {
        getTripForModification(tripId, userId);
        tripMapper.delete(tripId);
        tripSearchService.deleteTrip(tripId);
    }

    @Transactional
    public void replaceTripItems(Long tripId, TripItemsReplaceRequestDto dto, Long userId) {
        validateTripOwner(tripId, userId);

        tripMapper.deleteTripItemsByTripId(tripId);

        for (var day : dto.days()) {
            int order = 1;
            for (var item : day.items()) {
                Long spotId = resolveSpotId(item);
                tripMapper.insertTripItem(tripId, spotId, day.dayNumber(), order++);
            }
        }

        locationSummaryService.updateLocationSummary(tripId);
        
        // Sync to ES
        Trip trip = findTripById(tripId);
        List<TripItem> items = tripMapper.selectItemsWithSpotsByTripId(tripId);
        tripSearchService.saveTrip(trip, items);
    }

    private Long resolveSpotId(TripItemsReplaceRequestDto.Item item) {
        item.validate();

        if (item.spotId() != null) {
            spotService.validateExists(item.spotId());
            return item.spotId();
        }

        return spotService.findOrCreate(item.spot().toEntity()).getId();
    }

    public Trip findTripById(Long tripId) {
        return tripMapper.selectById(tripId)
                .orElseThrow(() -> new TripException(TripErrorCode.TRIP_NOT_FOUND));
    }

    private Trip getTripForModification(Long tripId, Long userId) {
        Trip trip = findTripById(tripId);
        if (!trip.getUserId().equals(userId)) {
            throw new TripException(TripErrorCode.FORBIDDEN_TRIP_ACCESS);
        }
        return trip;
    }

    private void validateTripOwner(Long tripId, Long userId) {
        if (!tripMapper.existsByIdAndUserId(tripId, userId)) {
            throw new TripException(TripErrorCode.FORBIDDEN_TRIP_ACCESS);
        }
    }

    public void validateTripExists(Long tripId) {
        if (tripMapper.selectById(tripId).isEmpty()) {
            throw new TripException(TripErrorCode.TRIP_NOT_FOUND);
        }
    }

    @Transactional
    public void completeTrip(Long tripId) {
        Trip trip = findTripById(tripId);
        if (trip.getStatus() != TripStatus.COMPLETED) {
            trip.setStatus(TripStatus.COMPLETED);
            tripMapper.update(trip);
        }
    }

    @Transactional
    public Long scrapTrip(Long tripId, Long userId) {
        Trip sourceTrip = getValidatedSourceTrip(tripId, userId);
        Trip newTrip = Trip.createScrap(sourceTrip, userId);
        
        tripMapper.insert(newTrip);
        copyTripItems(tripId, newTrip.getId());
        locationSummaryService.updateLocationSummary(newTrip.getId());
        
        // Sync new scrap trip (Private by default)
        List<TripItem> items = tripMapper.selectItemsWithSpotsByTripId(newTrip.getId());
        tripSearchService.saveTrip(newTrip, items);

        notificationService.send(userId, sourceTrip.getUserId(), NotificationType.SCRAP, null, tripId, "/trip/" + tripId);
        
        return newTrip.getId();
    }

    private Trip getValidatedSourceTrip(Long tripId, Long userId) {
        Trip trip = tripMapper.selectById(tripId)
                .orElseThrow(() -> new TripException(TripErrorCode.TRIP_NOT_FOUND));

        if (trip.getVisibility() == TripVisibility.PRIVATE && !trip.getUserId().equals(userId)) {
            throw new TripException(TripErrorCode.FORBIDDEN_TRIP_ACCESS);
        }
        return trip;
    }

    private void copyTripItems(Long sourceTripId, Long newTripId) {
        List<TripItem> sourceItems = tripMapper.selectItemsWithSpotsByTripId(sourceTripId);
        for (TripItem item : sourceItems) {
            tripMapper.insertTripItem(
                    newTripId,
                    item.getSpot().getId(), 
                    item.getDayNumber(),
                    item.getOrderIndex()
            );
        }
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
}
