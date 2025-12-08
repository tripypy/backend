package com.ssafy.jjtrip.domain.trip.service;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.service.SpotService;
import com.ssafy.jjtrip.domain.trip.dto.TripItemsUpdateRequestDto;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.exception.TripErrorCode;
import com.ssafy.jjtrip.domain.trip.exception.TripException;
import com.ssafy.jjtrip.domain.trip.mapper.TripMapper;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class TripItemsSynchronizer {

    private final Long tripId;
    private final TripItemsUpdateRequestDto requestDto;
    private final TripMapper tripMapper;
    private final SpotService spotService;

    private Map<Long, TripItem> existingItemsMap;
    private Set<Long> keptItemIds;

    public void sync() {
        this.existingItemsMap = tripMapper.selectItemsByTripId(this.tripId).stream()
                .collect(Collectors.toMap(TripItem::getId, item -> item));
        this.keptItemIds = new HashSet<>();

        if (!existingItemsMap.isEmpty()) {
            tripMapper.parkTripItems(new ArrayList<>(existingItemsMap.keySet()));
        }

        processTripItems();

        deleteStaleTripItems();
    }

    private void processTripItems() {
        requestDto.days().forEach(this::processSingleDay);
    }

    private void processSingleDay(TripItemsUpdateRequestDto.Day dayDto) {
        for (int i = 0; i < dayDto.items().size(); i++) {
            processSingleItem(dayDto.items().get(i), dayDto.dayNumber(), i + 1);
        }
    }

    private void processSingleItem(TripItemsUpdateRequestDto.ItemSync itemDto, int dayNumber, int orderIndex) {
        if (itemDto.tripItemId() != null) {
            updateExistingTripItem(itemDto, dayNumber, orderIndex);
        } else if (itemDto.spot() != null) {
            createNewTripItem(itemDto, dayNumber, orderIndex);
        }
    }

    private void updateExistingTripItem(TripItemsUpdateRequestDto.ItemSync itemDto, int dayNumber, int orderIndex) {
        Long id = itemDto.tripItemId();
        if (!this.existingItemsMap.containsKey(id)) {
            throw new TripException(TripErrorCode.INVALID_ITEMS_UPDATE_REQUEST);
        }
        this.keptItemIds.add(id);
        tripMapper.updateTripItemDetails(id, dayNumber, orderIndex, itemDto.memo());
    }

    private void createNewTripItem(TripItemsUpdateRequestDto.ItemSync itemDto, int dayNumber, int orderIndex) {
        Spot spot = spotService.findOrCreate(itemDto.spot().toEntity());
        TripItem newTripItem = TripItem.builder()
                .tripId(this.tripId)
                .spotId(spot.getId())
                .dayNumber(dayNumber)
                .orderIndex(orderIndex)
                .memo(itemDto.memo())
                .build();
        tripMapper.insertTripItem(newTripItem);
    }

    private void deleteStaleTripItems() {
        Set<Long> idsToDelete = new HashSet<>(this.existingItemsMap.keySet());
        idsToDelete.removeAll(this.keptItemIds);
        if (!idsToDelete.isEmpty()) {
            tripMapper.deleteTripItemsByIds(new ArrayList<>(idsToDelete));
        }
    }
}
