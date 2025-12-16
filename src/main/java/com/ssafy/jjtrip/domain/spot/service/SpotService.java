package com.ssafy.jjtrip.domain.spot.service;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.exception.SpotErrorCode;
import com.ssafy.jjtrip.domain.spot.exception.SpotException;
import com.ssafy.jjtrip.domain.spot.mapper.SpotMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
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
}
