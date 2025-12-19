package com.ssafy.jjtrip.domain.spot.service;

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


    public Spot createSpot(Spot spot) {
        if (spotMapper.findByKakaoPlaceId(spot.getKakaoPlaceId()).isPresent()) {
            throw new SpotException(SpotErrorCode.ALREADY_EXISTS);
        }
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
                    spotMapper.insert(spot);
                    return spot;
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
}
