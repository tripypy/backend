package com.ssafy.jjtrip.domain.trip.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.trip.dto.TripDetailResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripItemResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripItemsUpdateRequestDto;
import com.ssafy.jjtrip.domain.trip.dto.TripResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripUpdateRequestDto;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.service.TripService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
@RequestMapping("/trips")
@RequiredArgsConstructor
public class TripController {

    private final TripService tripService;

    @PostMapping
    public ResponseEntity<?> createTrip(@AuthenticationPrincipal CustomUserDetails userDetails) {
        Trip createdTrip = tripService.createTrip(userDetails.getUser().getId());
        TripDetailResponseDto responseDto = TripDetailResponseDto.from(createdTrip);

        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(createdTrip.getId())
                .toUri();

        return ResponseEntity.created(location).body(responseDto);
    }


    @GetMapping
    public ResponseEntity<?> getMyTrips(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam(value = "status", required = false) TripStatus status
    ) {
        List<TripResponseDto> myTrips = tripService.findMyTrips(userDetails.getUser().getId(), status);
        return ResponseEntity.ok(myTrips);
    }

    @GetMapping("/{tripId}")
    public ResponseEntity<?> getTripDetail(@PathVariable Long tripId, @AuthenticationPrincipal CustomUserDetails userDetails) {
        Trip trip = tripService.getTripDetail(tripId, userDetails.getUser().getId());
        TripDetailResponseDto responseDto = TripDetailResponseDto.from(trip);
        return ResponseEntity.ok(responseDto);
    }

    @PutMapping("/{tripId}")
    public ResponseEntity<?> updateTrip(@PathVariable Long tripId,
                                           @Valid @RequestBody TripUpdateRequestDto requestDto,
                                           @AuthenticationPrincipal CustomUserDetails userDetails) {
        tripService.updateTrip(tripId, requestDto, userDetails.getUser().getId());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{tripId}")
    public ResponseEntity<?> deleteTrip(@PathVariable Long tripId, @AuthenticationPrincipal CustomUserDetails userDetails) {
        tripService.deleteTrip(tripId, userDetails.getUser().getId());
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{tripId}/items")
    public ResponseEntity<?> updateAllTripItems(
            @PathVariable Long tripId,
            @Valid @RequestBody TripItemsUpdateRequestDto requestDto,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        List<TripItem> updatedItems = tripService.updateAllTripItems(tripId, requestDto, userDetails.getUser().getId());
        List<TripItemResponseDto> responseDtos = updatedItems.stream()
                .map(TripItemResponseDto::from)
                .collect(Collectors.toList());
        return ResponseEntity.ok(responseDtos);
    }
}
