package com.ssafy.jjtrip.domain.friend.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum FriendErrorCode implements ErrorCode {

    SELF_REQUEST(HttpStatus.BAD_REQUEST, "FRIEND-001", "자기 자신에게 친구 요청을 보낼 수 없습니다."),
    ALREADY_FRIENDS(HttpStatus.CONFLICT, "FRIEND-002", "이미 친구 관계입니다."),
    REQUEST_ALREADY_EXISTS(HttpStatus.CONFLICT, "FRIEND-003", "처리 대기 중이거나 이미 수락된 친구 요청이 존재합니다."),
    REQUEST_NOT_FOUND(HttpStatus.NOT_FOUND, "FRIEND-004", "존재하지 않는 친구 요청입니다."),
    NOT_THE_RECEIVER(HttpStatus.FORBIDDEN, "FRIEND-005", "친구요청을 받은 사용자만 처리할 수 있습니다."),
    NOT_THE_REQUESTER(HttpStatus.FORBIDDEN, "FRIEND-006", "친구요청을 보낸 사용자만 취소할 수 있습니다."),
    REQUEST_ALREADY_PROCESSED(HttpStatus.CONFLICT, "FRIEND-007", "이미 처리된 요청입니다."),
    FRIENDSHIP_NOT_FOUND(HttpStatus.NOT_FOUND, "FRIEND-008", "친구 관계를 찾을 수 없습니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;
}
