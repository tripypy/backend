package com.ssafy.jjtrip.domain.triplog.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.service.TripLogService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@RestController
@RequiredArgsConstructor
@RequestMapping("/trip-logs")
public class TripLogController {

    private final TripLogService tripLogService;

    @GetMapping("/{logId}")
    public TripLogDetailResponseDto getTripLogDetail(@PathVariable Long logId) {
        return tripLogService.getTripLogDetail(logId);
    }

    @PostMapping("/{logId}/comments")
    public ResponseEntity<Void> addComment(
            @PathVariable Long logId,
            @Valid @RequestBody TripLogCommentRequestDto commentRequestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogService.addComment(logId, userDetails.getUser().getId(), commentRequestDto);
        return ResponseEntity.created(URI.create("/trip-logs/" + logId)).build();
    }
}
