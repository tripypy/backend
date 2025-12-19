package com.ssafy.jjtrip.domain.spot.service;

import com.ssafy.jjtrip.domain.spot.dto.SpotReviewRequestDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotReviewResponseDto;
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
        if (!spotMapper.existsById(requestDto.spotId())) {
            throw new SpotException(SpotErrorCode.SPOT_NOT_FOUND);
        }

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
        if (!spotMapper.existsById(spotId)) {
            throw new SpotException(SpotErrorCode.SPOT_NOT_FOUND);
        }
        return spotReviewMapper.findBySpotId(spotId);
    }

    @Transactional
    public void updateReview(Long userId, Long reviewId, SpotReviewUpdateRequestDto requestDto) {
        SpotReview review = spotReviewMapper.findById(reviewId)
                .orElseThrow(() -> new SpotException(SpotErrorCode.REVIEW_NOT_FOUND)); // Assuming REVIEW_NOT_FOUND exists or use generic
        
        if (!review.getUserId().equals(userId)) {
             throw new SpotException(SpotErrorCode.FORBIDDEN_ACCESS); // Assuming FORBIDDEN_ACCESS exists
        }

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
        SpotReview review = spotReviewMapper.findById(reviewId)
                .orElseThrow(() -> new SpotException(SpotErrorCode.REVIEW_NOT_FOUND));

        if (!review.getUserId().equals(userId)) {
            throw new SpotException(SpotErrorCode.FORBIDDEN_ACCESS);
        }

        spotReviewMapper.delete(reviewId);
        updateSpotStats(review.getSpotId());
    }

    private void updateSpotStats(Long spotId) {
        int count = spotReviewMapper.countBySpotId(spotId);
        BigDecimal averageRating = spotReviewMapper.getAverageRating(spotId);
        spotMapper.updateReviewStats(spotId, count, averageRating);
    }
}
