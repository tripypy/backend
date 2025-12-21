package com.ssafy.jjtrip.domain.spot.controller;

import com.ssafy.jjtrip.domain.spot.dto.SpotRequestDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotResponseDto;
import com.ssafy.jjtrip.domain.spot.dto.SpotUpsertResult;
import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.service.SpotService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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
@RequestMapping("/spots")
@RequiredArgsConstructor
public class SpotController {

    private final SpotService spotService;

    @GetMapping
    public ResponseEntity<SpotResponseDto> getSpotByKakaoPlaceId(@RequestParam String kakaoPlaceId) {
        Spot spot = spotService.findByKakaoPlaceId(kakaoPlaceId);
        return ResponseEntity.ok(SpotResponseDto.from(spot));
    }

    @PostMapping
    public ResponseEntity<SpotResponseDto> createSpot(@RequestBody @Valid SpotRequestDto spotRequestDto) {
        Spot spot = spotRequestDto.toEntity();
        SpotUpsertResult result = spotService.upsertSpot(spot);
        
        if (result.isNew()) {
            return ResponseEntity.created(URI.create("/spots/" + result.spot().getId()))
                    .body(SpotResponseDto.from(result.spot()));
        } else {
            return ResponseEntity.ok(SpotResponseDto.from(result.spot()));
        }
    }

    @GetMapping("/{spotId}")
    public ResponseEntity<SpotResponseDto> getSpotById(@PathVariable Long spotId) {
        Spot spot = spotService.getSpotById(spotId);
        return ResponseEntity.ok(SpotResponseDto.from(spot));
    }

    @PatchMapping("/{spotId}")
    public ResponseEntity<SpotResponseDto> updateSpot(@PathVariable Long spotId, @RequestBody SpotRequestDto spotRequestDto) {
        Spot updatedSpot = spotService.updateSpot(spotId, spotRequestDto.toEntity());
        return ResponseEntity.ok(SpotResponseDto.from(updatedSpot));
    }

    @PostMapping("/{spotId}/thumbnail")
    public ResponseEntity<SpotResponseDto> updateSpotThumbnail(@PathVariable Long spotId) {
        Spot updatedSpot = spotService.updateSpotThumbnailWithGoogle(spotId);
        return ResponseEntity.ok(SpotResponseDto.from(updatedSpot));
    }

    @DeleteMapping("/{spotId}")
    public ResponseEntity<Void> deleteSpot(@PathVariable Long spotId) {
        spotService.deleteSpot(spotId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/hot")
    public ResponseEntity<List<SpotResponseDto>> getHotPlaces() {
        List<Spot> hotPlaces = spotService.getTop10HotPlaces();
        List<SpotResponseDto> response = hotPlaces.stream()
                .map(SpotResponseDto::from)
                .toList();
        return ResponseEntity.ok(response);
    }
}
