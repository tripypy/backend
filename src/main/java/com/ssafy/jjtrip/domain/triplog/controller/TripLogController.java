package com.ssafy.jjtrip.domain.triplog.controller;

import com.ssafy.jjtrip.common.dto.PageDto;
import com.ssafy.jjtrip.common.dto.SliceDto;
import com.ssafy.jjtrip.common.s3.dto.PresignedUrlResponseDto;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.triplog.dto.ImageUploadRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCreateRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCreateResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogFeedResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogLikeResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogUpdateRequestDto;
import com.ssafy.jjtrip.domain.triplog.service.TripLogCommentService;
import com.ssafy.jjtrip.domain.triplog.service.TripLogImageService;
import com.ssafy.jjtrip.domain.triplog.service.TripLogLikeService;
import com.ssafy.jjtrip.domain.triplog.service.TripLogService;
import jakarta.validation.Valid;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/trip-logs")
public class TripLogController {

    private final TripLogService tripLogService;
    private final TripLogImageService tripLogImageService;
    private final TripLogCommentService tripLogCommentService;
    private final TripLogLikeService tripLogLikeService;

    @PostMapping("/images/presigned-url")
    public ResponseEntity<PresignedUrlResponseDto> generatePresignedUrl(
            @Valid @RequestBody ImageUploadRequestDto imageUploadRequest,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        PresignedUrlResponseDto response = tripLogImageService.generatePresignedUrl(userDetails.getUser().getId(), imageUploadRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping
    public ResponseEntity<TripLogCreateResponseDto> createTripLog(
            @Valid @RequestBody TripLogCreateRequestDto requestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogCreateResponseDto response = tripLogService.createTripLog(userDetails.getUser().getId(), requestDto);
        return ResponseEntity.created(URI.create("/trip-logs/" + response.logId())).body(response);
    }

    @GetMapping
    public ResponseEntity<PageDto<TripLogFeedResponseDto>> getUserTripLogs(
            @RequestParam Long userId,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int limit,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        final Long memberId = (userDetails != null) ? userDetails.getUser().getId() : null;
        return ResponseEntity.ok(tripLogService.getUserTripLogs(userId, page, limit, memberId));
    }

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
    public ResponseEntity<?> getTripLogDetail(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        final Long memberId = (userDetails != null) ? userDetails.getUser().getId() : null;
        return ResponseEntity.ok(tripLogService.getTripLogDetail(logId, memberId));
    }

    @PatchMapping("/{logId}")
    public ResponseEntity<?> updateTripLog(
            @PathVariable Long logId,
            @Valid @RequestBody TripLogUpdateRequestDto requestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogService.updateTripLog(logId, userDetails.getUser().getId(), requestDto);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{logId}")
    public ResponseEntity<?> deleteTripLog(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogService.deleteTripLog(logId, userDetails.getUser().getId());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{logId}/comments")
    public ResponseEntity<?> addComment(
            @PathVariable Long logId,
            @Valid @RequestBody TripLogCommentRequestDto commentRequestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogCommentService.addComment(logId, userDetails.getUser().getId(), commentRequestDto);
        return ResponseEntity.created(URI.create("/trip-logs/" + logId)).build();
    }

    @PatchMapping("/comments/{commentId}")
    public ResponseEntity<?> updateComment(
            @PathVariable Long commentId,
            @Valid @RequestBody TripLogCommentRequestDto commentRequestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogCommentService.updateComment(userDetails.getUser().getId(), commentId, commentRequestDto.content());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/comments/{commentId}")
    public ResponseEntity<?> deleteComment(
            @PathVariable Long commentId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        tripLogCommentService.deleteComment(userDetails.getUser().getId(), commentId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{logId}/likes/status")
    public ResponseEntity<?> getLikeStatus(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogLikeResponseDto response = tripLogLikeService.getLikeStatus(logId, userDetails.getUser().getId());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{logId}/likes")
    public ResponseEntity<?> likeTripLog(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogLikeResponseDto response = tripLogLikeService.likeTripLog(logId, userDetails.getUser().getId());
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{logId}/likes")
    public ResponseEntity<?> unlikeTripLog(
            @PathVariable Long logId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        TripLogLikeResponseDto response = tripLogLikeService.unlikeTripLog(logId, userDetails.getUser().getId());
        return ResponseEntity.ok(response);
    }
}
