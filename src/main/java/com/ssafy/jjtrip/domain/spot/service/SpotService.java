package com.ssafy.jjtrip.domain.spot.service;

import com.ssafy.jjtrip.common.google.GoogleMapsClient;
import com.ssafy.jjtrip.common.google.dto.GoogleMapsDto.Place;
import com.ssafy.jjtrip.common.s3.S3Provider;
import com.ssafy.jjtrip.domain.spot.dto.SpotUpsertResult;
import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.exception.SpotErrorCode;
import com.ssafy.jjtrip.domain.spot.exception.SpotException;
import com.ssafy.jjtrip.domain.spot.mapper.SpotMapper;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class SpotService {

    private final SpotMapper spotMapper;
    private final S3Provider s3Provider;
    private final GoogleMapsClient googleMapsClient;


    public Spot createSpot(Spot spot) {
        if (spotMapper.findByKakaoPlaceId(spot.getKakaoPlaceId()).isPresent()) {
            throw new SpotException(SpotErrorCode.ALREADY_EXISTS);
        }
        
        enrichSpotWithGoogleImage(spot);
        
        spotMapper.insert(spot);
        return spot;
    }

    public Spot getSpotById(Long spotId) {
        return spotMapper.findById(spotId)
                .orElseThrow(() -> new SpotException(SpotErrorCode.SPOT_NOT_FOUND));
    }

    public Spot updateSpot(Long spotId, Spot updatedSpot) {
        Spot spot = getSpotById(spotId);

        if (updatedSpot.getName() != null) spot.setName(updatedSpot.getName());
        if (updatedSpot.getAddress() != null) spot.setAddress(updatedSpot.getAddress());
        if (updatedSpot.getCategory() != null) spot.setCategory(updatedSpot.getCategory());
        if (updatedSpot.getLat() != null) spot.setLat(updatedSpot.getLat());
        if (updatedSpot.getLng() != null) spot.setLng(updatedSpot.getLng());
        if (updatedSpot.getPlaceUrl() != null) spot.setPlaceUrl(updatedSpot.getPlaceUrl());
        if (updatedSpot.getThumbnailUrl() != null) spot.setThumbnailUrl(updatedSpot.getThumbnailUrl());

        spotMapper.update(spot);
        return spot;
    }

    public void deleteSpot(Long spotId) {
        validateExists(spotId);
        spotMapper.delete(spotId);
    }

    public Spot findOrCreate(Spot spot) {
        return spotMapper.findByKakaoPlaceId(spot.getKakaoPlaceId())
                .orElseGet(() -> {
                    enrichSpotWithGoogleImage(spot);
                    spotMapper.insert(spot);
                    return spot;
                });
    }

    public SpotUpsertResult upsertSpot(Spot spot) {
        return spotMapper.findByKakaoPlaceId(spot.getKakaoPlaceId())
                .map(existingSpot -> new SpotUpsertResult(existingSpot, false))
                .orElseGet(() -> {
                    enrichSpotWithGoogleImage(spot);
                    spotMapper.insert(spot);
                    return new SpotUpsertResult(spot, true);
                });
    }

    public Spot findByKakaoPlaceId(String kakaoPlaceId) {
        return spotMapper.findByKakaoPlaceId(kakaoPlaceId)
                .orElseThrow(() -> new SpotException(SpotErrorCode.SPOT_NOT_FOUND));
    }

    public void validateExists(Long spotId) {
        if (!spotMapper.existsById(spotId)) {
            throw new SpotException(SpotErrorCode.SPOT_NOT_FOUND);
        }
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "hotPlaces", key = "'top10'")
    public List<Spot> getTop10HotPlaces() {
        return spotMapper.findTop10MostAdded();
    }

    @Scheduled(fixedRateString = "${app.cache.hot-place-refresh-rate:600000}")
    @CacheEvict(value = "hotPlaces", allEntries = true)
    public void evictHotPlacesCache() {
        log.info("Hot Place 캐시가 갱신되었습니다.");
    }

    private void enrichSpotWithGoogleImage(Spot spot) {
        if (hasThumbnail(spot)) return;

        byte[] imageBytes = fetchGooglePlaceImage(spot);
        if (imageBytes == null || imageBytes.length == 0) return;

        String uploadedUrl = uploadImageToS3(spot, imageBytes);
        if (uploadedUrl != null) {
            spot.setThumbnailUrl(uploadedUrl);
            log.info("Successfully uploaded Google Maps photo to S3: {}", uploadedUrl);
        }
    }

    private byte[] fetchGooglePlaceImage(Spot spot) {
        try {
            log.info("Fetching photo from Google Maps for spot: {}", spot.getName());
            Place place = googleMapsClient.searchPlace(spot.getName(), spot.getLat(), spot.getLng());
            
            if (place != null && place.photos() != null && !place.photos().isEmpty()) {
                return googleMapsClient.fetchPhoto(place.photos().get(0).name());
            }
        } catch (Exception e) {
            log.error("Failed to fetch Google Place image: {}", e.getMessage());
        }
        return null;
    }

    private boolean hasThumbnail(Spot spot) {
        return spot.getThumbnailUrl() != null && !spot.getThumbnailUrl().isBlank();
    }

    private String uploadImageToS3(Spot spot, byte[] imageBytes) {
        try {
            return s3Provider.upload(
                imageBytes, 
                spot.getName() + ".jpg", 
                "image/jpeg", 
                "spots/" + spot.getKakaoPlaceId() + "/"
            );
        } catch (Exception e) {
            log.error("Failed to upload image to S3: {}", e.getMessage());
            return null;
        }
    }
}
