package com.ssafy.jjtrip.domain.friend.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.friend.dto.request.FriendRequestRequestDto;
import com.ssafy.jjtrip.domain.friend.dto.response.FriendRequestResponseDto;
import com.ssafy.jjtrip.domain.friend.dto.response.SimpleUserInfoDto;
import com.ssafy.jjtrip.domain.friend.service.FriendService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/friends")
@RequiredArgsConstructor
public class FriendController {

    private final FriendService friendService;

    @PostMapping("/requests")
    public ResponseEntity<Void> sendFriendRequest(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @Valid @RequestBody FriendRequestRequestDto requestDto
    ) {
        Long requesterId = userDetails.getUser().getId();
        friendService.sendRequest(requesterId, requestDto.getReceiverId());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/requests/received")
    public ResponseEntity<List<FriendRequestResponseDto>> getReceivedRequests(
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long userId = userDetails.getUser().getId();
        List<FriendRequestResponseDto> receivedRequests = friendService.getReceivedRequests(userId);
        return ResponseEntity.ok(receivedRequests);
    }

    @GetMapping("/requests/sent")
    public ResponseEntity<List<FriendRequestResponseDto>> getSentRequests(
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long userId = userDetails.getUser().getId();
        List<FriendRequestResponseDto> sentRequests = friendService.getSentRequests(userId);
        return ResponseEntity.ok(sentRequests);
    }

    @PostMapping("/requests/{requestId}/accept")
    public ResponseEntity<Void> acceptRequest(
            @PathVariable Long requestId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long acceptingUserId = userDetails.getUser().getId();
        friendService.acceptRequest(requestId, acceptingUserId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build(); // 204 No Content for successful update/delete
    }

    @PostMapping("/requests/{requestId}/decline")
    public ResponseEntity<Void> declineRequest(
            @PathVariable Long requestId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long decliningUserId = userDetails.getUser().getId();
        friendService.declineRequest(requestId, decliningUserId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build(); // 204 No Content for successful update/delete
    }

    @DeleteMapping("/requests/sent/{requestId}")
    public ResponseEntity<Void> cancelSentRequest(
            @PathVariable Long requestId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long cancellingUserId = userDetails.getUser().getId();
        friendService.cancelSentRequest(requestId, cancellingUserId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @GetMapping
    public ResponseEntity<List<SimpleUserInfoDto>> getFriendList(
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long userId = userDetails.getUser().getId();
        List<SimpleUserInfoDto> friendList = friendService.getFriendList(userId);
        return ResponseEntity.ok(friendList);
    }

    @DeleteMapping("/{friendId}")
    public ResponseEntity<Void> deleteFriend(
            @PathVariable Long friendId,
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        Long myUserId = userDetails.getUser().getId();
        friendService.deleteFriend(myUserId, friendId);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}