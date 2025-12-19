package com.ssafy.jjtrip.domain.spot.service;

import com.ssafy.jjtrip.domain.spot.dto.SpotReviewRequestDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewResponseDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewStatsResponseDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewUpdateRequestDto;
import com.ssafy.jjtrip.domain.spot.entity.SpotReview;
import com.ssafy.jjtrip.domain.spot.exception.SpotErrorCode;
import com.ssafy.jjtrip.domain.spot.exception.SpotException;
import com.ssafy.jjtrip.domain.spot.mapper.SpotMapper;
import com.ssafy.jjtrip.domain.spot.mapper.SpotReviewMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SpotReviewService {

    private final SpotReviewMapper spotReviewMapper;
    private final SpotMapper spotMapper;

    @Transactional
    public Long createReview(Long userId, SpotReviewRequestDto requestDto) {
        validateSpotExists(requestDto.spotId());
        validateDuplicateReview(userId, requestDto.spotId());

        SpotReview review = SpotReview.builder()
                .spotId(requestDto.spotId())
                .userId(userId)
                .rating(requestDto.rating())
                .content(requestDto.content())
                .build();

        spotReviewMapper.insert(review);
        updateSpotStats(requestDto.spotId());

        return review.getId();
    }

    public List<SpotReviewResponseDto> getReviews(Long spotId) {
        validateSpotExists(spotId);
        return spotReviewMapper.findBySpotId(spotId);
    }

    @Transactional
    public void updateReview(Long userId, Long reviewId, SpotReviewUpdateRequestDto requestDto) {
        SpotReview review = findReviewByIdOrThrow(reviewId);
        validateReviewOwner(userId, review);

        if (requestDto.rating() != null) {
            review.setRating(requestDto.rating());
        }
        if (requestDto.content() != null) {
            review.setContent(requestDto.content());
        }

        spotReviewMapper.update(review);
        updateSpotStats(review.getSpotId());
    }

    @Transactional
    public void deleteReview(Long userId, Long reviewId) {
        SpotReview review = findReviewByIdOrThrow(reviewId);
        validateReviewOwner(userId, review);

        spotReviewMapper.delete(reviewId);
        updateSpotStats(review.getSpotId());
    }

    public SpotReviewStatsResponseDto getReviewStats(Long spotId) {
        validateSpotExists(spotId);
        int count = spotReviewMapper.countBySpotId(spotId);
        BigDecimal averageRating = spotReviewMapper.getAverageRating(spotId);
        return new SpotReviewStatsResponseDto(averageRating, count);
    }

    private void updateSpotStats(Long spotId) {
        int count = spotReviewMapper.countBySpotId(spotId);
        BigDecimal averageRating = spotReviewMapper.getAverageRating(spotId);
        spotMapper.updateReviewStats(spotId, count, averageRating);
    }

    private void validateSpotExists(Long spotId) {
        if (!spotMapper.existsById(spotId)) {
            throw new SpotException(SpotErrorCode.SPOT_NOT_FOUND);
        }
    }

    private void validateDuplicateReview(Long userId, Long spotId) {
        if (spotReviewMapper.existsBySpotIdAndUserId(spotId, userId)) {
            throw new SpotException(SpotErrorCode.ALREADY_REVIEWED);
        }
    }

    private SpotReview findReviewByIdOrThrow(Long reviewId) {
        return spotReviewMapper.findById(reviewId)
                .orElseThrow(() -> new SpotException(SpotErrorCode.REVIEW_NOT_FOUND));
    }

    private void validateReviewOwner(Long userId, SpotReview review) {
        if (!review.getUserId().equals(userId)) {
            throw new SpotException(SpotErrorCode.FORBIDDEN_ACCESS);
        }
    }
}
