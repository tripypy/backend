package com.ssafy.jjtrip.domain.friend.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.friend.dto.request.FriendRequestRequestDto;
import com.ssafy.jjtrip.domain.friend.service.FriendshipService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/friends")
@RequiredArgsConstructor
public class FriendshipController {

    private final FriendshipService friendshipService;

    @PostMapping("/requests")
    public ResponseEntity<Void> sendFriendRequest(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @Valid @RequestBody FriendRequestRequestDto requestDto
    ) {
        Long requesterId = userDetails.getUser().getId();
        friendshipService.sendRequest(requesterId, requestDto.getReceiverId());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
