package com.ssafy.jjtrip.domain.spot.controller;

import com.ssafy.jjtrip.domain.spot.dto.SpotResponseDto;
import com.ssafy.jjtrip.domain.spot.entity.Spot;
import com.ssafy.jjtrip.domain.spot.service.SpotService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/spots")
@RequiredArgsConstructor
public class SpotController {

    private final SpotService spotService;

    @GetMapping("/hot")
    public ResponseEntity<List<SpotResponseDto>> getHotPlaces() {
        List<Spot> hotPlaces = spotService.getTop10HotPlaces();
        List<SpotResponseDto> response = hotPlaces.stream()
                .map(SpotResponseDto::from)
                .toList();
        return ResponseEntity.ok(response);
    }
}
