package com.ssafy.jjtrip.domain.triplog.controller;

import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.service.TripLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/trip-logs")
public class TripLogController {

    private final TripLogService tripLogService;

    @GetMapping("/{logId}")
    public TripLogDetailResponseDto getTripLogDetail(@PathVariable Long logId) {
        return tripLogService.getTripLogDetail(logId);
    }
}
