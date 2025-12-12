package com.ssafy.jjtrip.domain.triplog.controller;

import com.ssafy.jjtrip.common.dto.SliceDto;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogFeedResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogLikeResponseDto;
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

    @GetMapping("/feed")
    public ResponseEntity<SliceDto<TripLogFeedResponseDto>> getTripLogFeed(
            @RequestParam(required = false) Long cursor,
            @RequestParam(defaultValue = "10") int limit,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        final Long memberId = (userDetails != null) ? userDetails.getUser().getId() : null;
        return ResponseEntity.ok(tripLogService.getTripLogFeed(cursor, limit, memberId));
    }

    @GetMapping("/{logId}")
    public ResponseEntity<?> getTripLogDetail(@PathVariable Long logId) {
        return ResponseEntity.ok(tripLogService.getTripLogDetail(logId));
    }

    @PostMapping("/{logId}/comments")
    public ResponseEntity<?> addComment(
            @PathVariable Long logId,
            @Valid @RequestBody TripLogCommentRequestDto commentRequestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogService.addComment(logId, userDetails.getUser().getId(), commentRequestDto);
        return ResponseEntity.created(URI.create("/trip-logs/" + logId)).build();
    }

    @GetMapping("/{logId}/likes/status")
    public ResponseEntity<?> getLikeStatus(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogLikeResponseDto response = tripLogService.getLikeStatus(logId, userDetails.getUser().getId());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{logId}/likes")
    public ResponseEntity<?> likeTripLog(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogLikeResponseDto response = tripLogService.likeTripLog(logId, userDetails.getUser().getId());
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{logId}/likes")
    public ResponseEntity<?> unlikeTripLog(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogLikeResponseDto response = tripLogService.unlikeTripLog(logId, userDetails.getUser().getId());
        return ResponseEntity.ok(response);
    }
}
