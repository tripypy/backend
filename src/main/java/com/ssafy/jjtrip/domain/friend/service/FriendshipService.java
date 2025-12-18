package com.ssafy.jjtrip.domain.friend.service;

import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequest;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequestStatus;
import com.ssafy.jjtrip.domain.friend.exception.FriendErrorCode;
import com.ssafy.jjtrip.domain.friend.exception.FriendException;
import com.ssafy.jjtrip.domain.friend.mapper.FriendshipMapper;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class FriendshipService {

    private final FriendshipMapper friendshipMapper;
    private final UserMapper userMapper;

    @Transactional
    public void sendRequest(Long requesterId, Long receiverId) {
        // 1. 자기 자신에게 요청하는지 검증
        if (requesterId.equals(receiverId)) {
            throw new FriendException(FriendErrorCode.SELF_REQUEST);
        }

        // 2. 요청을 받는 사용자가 존재하는지 검증
        userMapper.findById(receiverId)
                .orElseThrow(() -> new FriendException(AuthErrorCode.USER_NOT_FOUND));

        // 3. 이미 친구인지 검증
        long userIdA = Math.min(requesterId, receiverId);
        long userIdB = Math.max(requesterId, receiverId);
        friendshipMapper.findFriendshipByUsers(userIdA, userIdB).ifPresent(friendship -> {
            throw new FriendException(FriendErrorCode.ALREADY_FRIENDS);
        });

        // 4. 이미 처리 대기 중인 요청이 있는지 검증 (양방향)
        friendshipMapper.findRequestByUsers(requesterId, receiverId).ifPresent(request -> {
            if (request.getStatus() == FriendRequestStatus.PENDING || request.getStatus() == FriendRequestStatus.ACCEPTED) {
                throw new FriendException(FriendErrorCode.REQUEST_ALREADY_EXISTS);
            }
        });

        // 5. 모든 검증 통과 후 요청 생성
        FriendRequest friendRequest = FriendRequest.builder()
                .requesterId(requesterId)
                .receiverId(receiverId)
                .status(FriendRequestStatus.PENDING)
                .build();
        friendshipMapper.saveRequest(friendRequest);
    }
}
