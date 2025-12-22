package com.ssafy.jjtrip.domain.notification.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum NotificationErrorCode implements ErrorCode {

    NOTIFICATION_NOT_FOUND(HttpStatus.NOT_FOUND, "NOTI-001", "알림을 찾을 수 없습니다."),
    SSE_CONNECTION_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "NOTI-002", "알림 서버 연결 중 오류가 발생했습니다."),
    SENDER_NOT_FOUND(HttpStatus.NOT_FOUND, "NOTI-003", "알림 발송자를 찾을 수 없습니다."),
    FORBIDDEN_ACCESS(HttpStatus.FORBIDDEN, "NOTI-004", "해당 알림에 대한 접근 권한이 없습니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;
}
