package com.ssafy.jjtrip.domain.trip.service;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.service.SpotService;
import com.ssafy.jjtrip.domain.trip.dto.TripItemAddRequestDto;
import com.ssafy.jjtrip.domain.trip.dto.TripUpdateRequestDto;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.exception.TripErrorCode;
import com.ssafy.jjtrip.domain.trip.exception.TripException;
import com.ssafy.jjtrip.domain.trip.mapper.TripMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripService {

    private final TripMapper tripMapper;
    private final SpotService spotService;

    @Transactional
    public Trip createTrip(Long userId) {
        Trip newTrip = Trip.builder()
                .userId(userId)
                .title("임시 여행") // 기본 제목
                .status(TripStatus.DRAFT) // 기본 상태
                .build();
        tripMapper.insert(newTrip);
        return newTrip;
    }

    public List<Trip> findMyTrips(Long userId, TripStatus status) {
        if (status == null) {
            return tripMapper.selectByUserId(userId);
        } else {
            return tripMapper.selectByUserIdAndStatus(userId, status);
        }
    }

    public Trip getTripDetail(Long tripId, Long userId) {
        Trip trip = findTripById(tripId);

        if (trip.getStatus() != TripStatus.PUBLIC && !trip.getUserId().equals(userId)) {
            throw new TripException(TripErrorCode.FORBIDDEN_TRIP_ACCESS);
        }

        List<TripItem> tripItems = tripMapper.selectItemsByTripId(tripId);
        trip.setTripItems(tripItems);
        return trip;
    }

    @Transactional
    public void updateTrip(Long tripId, TripUpdateRequestDto requestDto, Long userId) {
        Trip trip = getTripForModification(tripId, userId);

        trip.setTitle(requestDto.title());
        trip.setStartDate(requestDto.startDate());
        trip.setEndDate(requestDto.endDate());
        trip.setStatus(requestDto.status());
        tripMapper.update(trip);
    }

    @Transactional
    public void deleteTrip(Long tripId, Long userId) {
        getTripForModification(tripId, userId);
        tripMapper.delete(tripId);
    }

    @Transactional
    public TripItem addTripItem(Long tripId, Long userId, TripItemAddRequestDto requestDto) {
        getTripForModification(tripId, userId);

        // 해당 위치에 이미 아이템이 존재하는지 확인
        if (tripMapper.existsByTripIdAndDayNumberAndOrderIndex(
                tripId, requestDto.dayNumber(), requestDto.orderIndex())) {
            throw new TripException(TripErrorCode.ITEM_POSITION_ALREADY_EXISTS);
        }

        Spot spot = spotService.findOrCreate(requestDto.spot().toEntity());
        return createAndSaveTripItem(tripId, spot, requestDto);
    }

    private Trip findTripById(Long tripId) {
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

    private TripItem createAndSaveTripItem(Long tripId, Spot spot, TripItemAddRequestDto requestDto) {
        TripItem tripItem = TripItem.builder()
                .tripId(tripId)
                .spotId(spot.getId())
                .dayNumber(requestDto.dayNumber())
                .orderIndex(requestDto.orderIndex())
                .memo(requestDto.memo())
                .build();
        tripMapper.insertTripItem(tripItem);
        return tripItem;
    }
}
