package com.ssafy.jjtrip.domain.search.controller;

import com.ssafy.jjtrip.domain.search.dto.TripLogSearchDoc;
import com.ssafy.jjtrip.domain.search.dto.TripSearchDoc;
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

    private final TripLogSearchService tripLogSearchService;
    private final TripSearchService tripSearchService;

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
