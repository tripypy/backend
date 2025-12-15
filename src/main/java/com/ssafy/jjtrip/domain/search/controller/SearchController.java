package com.ssafy.jjtrip.domain.search.controller;

import com.ssafy.jjtrip.domain.search.dto.SpotSearchDoc;
import com.ssafy.jjtrip.domain.search.dto.TripLogSearchDoc;
import com.ssafy.jjtrip.domain.search.dto.TripSearchDoc;
import com.ssafy.jjtrip.domain.search.service.SpotSearchService;
import com.ssafy.jjtrip.domain.search.service.TripLogSearchService;
import com.ssafy.jjtrip.domain.search.service.TripSearchService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/search")
public class SearchController {

    private final SpotSearchService spotSearchService;
    private final TripLogSearchService tripLogSearchService;
    private final TripSearchService tripSearchService;

    @GetMapping("/spots")
    public ResponseEntity<List<SpotSearchDoc>> searchSpots(@RequestParam("q") String keyword) {
        List<SpotSearchDoc> result = spotSearchService.search(keyword);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/trip-logs")
    public ResponseEntity<List<TripLogSearchDoc>> searchTripLogs(@RequestParam("q") String keyword) {
        List<TripLogSearchDoc> result = tripLogSearchService.search(keyword);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/trips")
    public ResponseEntity<List<TripSearchDoc>> searchTrips(@RequestParam("q") String keyword) {
        List<TripSearchDoc> result = tripSearchService.search(keyword);
        return ResponseEntity.ok(result);
    }
}
