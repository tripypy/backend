package com.ssafy.jjtrip.domain.trip.service;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.exception.TripErrorCode;
import com.ssafy.jjtrip.domain.trip.exception.TripException;
import com.ssafy.jjtrip.domain.trip.mapper.TripMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class LocationSummaryService {

    private final TripMapper tripMapper;

    public void updateLocationSummary(Long tripId) {
        Trip trip = tripMapper.selectById(tripId)
                .orElseThrow(() -> new TripException(TripErrorCode.TRIP_NOT_FOUND));

        List<TripItem> items = tripMapper.selectItemsWithSpotsByTripId(tripId);
        List<String> addresses = items.stream()
                .map(item -> item.getSpot().getAddress())
                .collect(Collectors.toList());

        String locationSummary = calculateLongestCommonPrefix(addresses);

        trip.setLocationSummary(locationSummary);
        tripMapper.update(trip);
    }

    private String calculateLongestCommonPrefix(List<String> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return "";
        }

        String[] firstAddressParts = addresses.get(0).split(" ");
        if (addresses.size() == 1) {
            return firstAddressParts.length > 1 ? firstAddressParts[0] + " " + firstAddressParts[1] : firstAddressParts[0];
        }

        String firstAddress = addresses.get(0);
        int commonPrefixLength = firstAddress.length();

        for (int i = 1; i < addresses.size(); i++) {
            commonPrefixLength = Math.min(commonPrefixLength, addresses.get(i).length());
            for (int j = 0; j < commonPrefixLength; j++) {
                if (firstAddress.charAt(j) != addresses.get(i).charAt(j)) {
                    commonPrefixLength = j;
                    break;
                }
            }
        }

        String commonPrefix = firstAddress.substring(0, commonPrefixLength);
        int lastSpace = commonPrefix.lastIndexOf(' ');
        if (lastSpace != -1) {
            return commonPrefix.substring(0, lastSpace).trim();
        } else {
            return commonPrefix.trim();
        }
    }
}
