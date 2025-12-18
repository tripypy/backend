package com.ssafy.jjtrip.domain.spot.service;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.exception.SpotErrorCode;
import com.ssafy.jjtrip.domain.spot.exception.SpotException;
import com.ssafy.jjtrip.domain.spot.mapper.SpotMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class SpotService {

    private final SpotMapper spotMapper;

    public Spot findOrCreate(Spot spot) {
        return spotMapper.findByKakaoPlaceId(spot.getKakaoPlaceId())
                .orElseGet(() -> {
                    spotMapper.insert(spot);
                    return spot;
                });
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
