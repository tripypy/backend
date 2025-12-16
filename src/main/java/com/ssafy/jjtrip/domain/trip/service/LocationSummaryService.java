package com.ssafy.jjtrip.domain.trip.service;

import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.exception.TripErrorCode;
import com.ssafy.jjtrip.domain.trip.exception.TripException;
import com.ssafy.jjtrip.domain.trip.mapper.TripMapper;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class LocationSummaryService {

    private final TripMapper tripMapper;

    public void updateLocationSummary(Long tripId) {
        tripMapper.selectById(tripId)
                .orElseThrow(() -> new TripException(TripErrorCode.TRIP_NOT_FOUND));

        List<TripItem> items = tripMapper.selectItemsWithSpotsByTripId(tripId);

        List<String> addresses = items.stream()
                .map(i -> i.getSpot().getAddress())
                .filter(a -> a != null && !a.isBlank())
                .toList();

        String locationSummary = calculateLocationSummary(addresses);

        tripMapper.updateLocationSummary(tripId, locationSummary);
    }

    private String calculateLocationSummary(List<String> addresses) {
        if (addresses == null || addresses.isEmpty()) return "";

        // 1개면 "시/도 + 구/군" 정도
        String[] parts = addresses.get(0).split(" ");
        if (addresses.size() == 1) {
            return parts.length >= 2 ? parts[0] + " " + parts[1] : parts[0];
        }

        // 기존 로직(공통 prefix 기반) 사용
        return calculateLongestCommonPrefix(addresses);
    }

    private String calculateLongestCommonPrefix(List<String> addresses) {
        String first = addresses.get(0);
        int len = first.length();

        for (int i = 1; i < addresses.size(); i++) {
            len = Math.min(len, addresses.get(i).length());
            for (int j = 0; j < len; j++) {
                if (first.charAt(j) != addresses.get(i).charAt(j)) {
                    len = j;
                    break;
                }
            }
        }

        String prefix = first.substring(0, len);
        int lastSpace = prefix.lastIndexOf(' ');
        return (lastSpace != -1) ? prefix.substring(0, lastSpace).trim() : prefix.trim();
    }
}
