package com.ssafy.jjtrip.domain.friend.service;

import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.friend.dto.response.FriendRequestResponseDto;
import com.ssafy.jjtrip.domain.friend.dto.response.SimpleUserInfoDto;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequest;
import com.ssafy.jjtrip.domain.friend.entity.Friendship;
import com.ssafy.jjtrip.domain.friend.exception.FriendErrorCode;
import com.ssafy.jjtrip.domain.friend.exception.FriendException;
import com.ssafy.jjtrip.domain.friend.mapper.FriendMapper;
import com.ssafy.jjtrip.domain.notification.entity.NotificationType;
import com.ssafy.jjtrip.domain.notification.service.NotificationService;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class FriendService {

    private final FriendMapper friendMapper;
    private final UserMapper userMapper;
    private final NotificationService notificationService;

    @PostConstruct
    @Transactional
    public void init() {
        userMapper.syncAllFriendsCounts();
    }

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
        friendMapper.findFriendshipByUsers(userIdA, userIdB).ifPresent(friendship -> {
            throw new FriendException(FriendErrorCode.ALREADY_FRIENDS);
        });

        // 4. 이미 처리 대기 중인 요청이 있는지 검증 (양방향)
        friendMapper.findRequestByUsers(requesterId, receiverId).ifPresent(request -> {
            throw new FriendException(FriendErrorCode.REQUEST_ALREADY_EXISTS);
        });

        // 5. 모든 검증 통과 후 요청 생성
        FriendRequest friendRequest = FriendRequest.builder()
                .requesterId(requesterId)
                .receiverId(receiverId)
                .build();
        friendMapper.saveRequest(friendRequest);

        notificationService.send(requesterId, receiverId, NotificationType.FRIEND_REQUEST, null, requesterId, "/friends");
    }

    public List<FriendRequestResponseDto> getReceivedRequests(Long userId) {
        return friendMapper.findReceivedRequestsByUserId(userId);
    }

    public List<FriendRequestResponseDto> getSentRequests(Long userId) {
        return friendMapper.findSentRequestsByUserId(userId);
    }

    @Transactional
    public void acceptRequest(Long requestId, Long acceptingUserId) {
        FriendRequest friendRequest = friendMapper.findRequestById(requestId)
                .orElseThrow(() -> new FriendException(FriendErrorCode.REQUEST_NOT_FOUND));

        // 요청을 수락하는 사용자가 해당 요청의 수신자인지 확인
        if (!friendRequest.getReceiverId().equals(acceptingUserId)) {
            throw new FriendException(FriendErrorCode.NOT_THE_RECEIVER);
        }
        
        // friendship 테이블에 친구 관계 추가 (중복 방지를 위해 항상 작은 ID, 큰 ID 순서로 저장)
        long userIdA = Math.min(friendRequest.getRequesterId(), friendRequest.getReceiverId());
        long userIdB = Math.max(friendRequest.getRequesterId(), friendRequest.getReceiverId());

        friendMapper.findFriendshipByUsers(userIdA, userIdB).ifPresent(friendship -> {
            throw new FriendException(FriendErrorCode.ALREADY_FRIENDS);
        });

        Friendship friendship = Friendship.builder()
                .userIdA(userIdA)
                .userIdB(userIdB)
                .build();
        friendMapper.saveFriendship(friendship);

        // 양쪽 유저의 친구 수 증가
        userMapper.incrementFriendsCount(friendRequest.getRequesterId());
        userMapper.incrementFriendsCount(friendRequest.getReceiverId());

        notificationService.send(acceptingUserId, friendRequest.getRequesterId(), NotificationType.FRIEND_ACCEPT, null, acceptingUserId, "/friends");

        // 친구 요청 기록 삭제
        friendMapper.deleteRequestById(requestId);
    }

    @Transactional
    public void declineRequest(Long requestId, Long decliningUserId) {
        FriendRequest friendRequest = friendMapper.findRequestById(requestId)
                .orElseThrow(() -> new FriendException(FriendErrorCode.REQUEST_NOT_FOUND));

        // 요청을 거절하는 사용자가 해당 요청의 수신자인지 확인
        if (!friendRequest.getReceiverId().equals(decliningUserId)) {
            throw new FriendException(FriendErrorCode.NOT_THE_RECEIVER);
        }

        // 친구 요청 기록 삭제
        friendMapper.deleteRequestById(requestId);
    }

    @Transactional
    public void cancelSentRequest(Long requestId, Long cancellingUserId) {
        FriendRequest friendRequest = friendMapper.findRequestById(requestId)
                .orElseThrow(() -> new FriendException(FriendErrorCode.REQUEST_NOT_FOUND));

        // 요청을 취소하는 사용자가 해당 요청의 송신자인지 확인
        if (!friendRequest.getRequesterId().equals(cancellingUserId)) {
            throw new FriendException(FriendErrorCode.NOT_THE_REQUESTER);
        }

        // 친구 요청 기록 삭제
        friendMapper.deleteRequestById(requestId);
    }

    public List<SimpleUserInfoDto> getFriendList(Long userId) {
        return friendMapper.findFriendsByUserId(userId);
    }

    @Transactional
    public void deleteFriend(Long myUserId, Long friendId) {
        // 1. 친구 ID가 유효한지 검증
        userMapper.findById(friendId)
                .orElseThrow(() -> new FriendException(AuthErrorCode.USER_NOT_FOUND));

        // 2. 친구 관계가 존재하는지 검증
        long userIdA = Math.min(myUserId, friendId);
        long userIdB = Math.max(myUserId, friendId);
        friendMapper.findFriendshipByUsers(userIdA, userIdB)
                .orElseThrow(() -> new FriendException(FriendErrorCode.FRIENDSHIP_NOT_FOUND));

        // 3. 친구 관계 삭제
        friendMapper.deleteFriendship(userIdA, userIdB);

        // 양쪽 유저의 친구 수 감소
        userMapper.decrementFriendsCount(myUserId);
        userMapper.decrementFriendsCount(friendId);
    }
}
