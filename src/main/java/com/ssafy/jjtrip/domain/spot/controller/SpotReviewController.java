package com.ssafy.jjtrip.domain.spot.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewRequestDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewResponseDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewUpdateRequestDto;
import com.ssafy.jjtrip.domain.spot.service.SpotReviewService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
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
@RequestMapping("/spot-reviews")
@RequiredArgsConstructor
public class SpotReviewController {

    private final SpotReviewService spotReviewService;

    @PostMapping
    public ResponseEntity<Void> createReview(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @Valid @RequestBody SpotReviewRequestDto requestDto
    ) {
        Long reviewId = spotReviewService.createReview(userDetails.getUser().getId(), requestDto);
        return ResponseEntity.created(URI.create("/spot-reviews/" + reviewId)).build();
    }

    @GetMapping
    public ResponseEntity<List<SpotReviewResponseDto>> getReviews(@RequestParam Long spotId) {
        return ResponseEntity.ok(spotReviewService.getReviews(spotId));
    }

    @PatchMapping("/{reviewId}")
    public ResponseEntity<Void> updateReview(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable Long reviewId,
            @Valid @RequestBody SpotReviewUpdateRequestDto requestDto
    ) {
        spotReviewService.updateReview(userDetails.getUser().getId(), reviewId, requestDto);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{reviewId}")
    public ResponseEntity<Void> deleteReview(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable Long reviewId
    ) {
        spotReviewService.deleteReview(userDetails.getUser().getId(), reviewId);
        return ResponseEntity.noContent().build();
    }
}
