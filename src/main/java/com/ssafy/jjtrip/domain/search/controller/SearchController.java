package com.ssafy.jjtrip.domain.search.controller;

import com.ssafy.jjtrip.domain.search.dto.SpotSearchDoc;
import com.ssafy.jjtrip.domain.search.service.SpotSearchService;
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

    @GetMapping("/spots")
    public ResponseEntity<List<SpotSearchDoc>> searchSpots(@RequestParam("q") String keyword) {
        List<SpotSearchDoc> result = spotSearchService.search(keyword);
        return ResponseEntity.ok(result);
    }
}
