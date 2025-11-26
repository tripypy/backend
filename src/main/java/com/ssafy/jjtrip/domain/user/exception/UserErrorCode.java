package com.ssafy.jjtrip.domain.user.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum UserErrorCode implements ErrorCode {

    INVALID_ROLE_ID("USER_001", "DB에 유효하지 않은 Role ID가 존재합니다.", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_USER_STATUS_ID("USER_002", "DB에 유효하지 않은 User Status ID가 존재합니다.", HttpStatus.INTERNAL_SERVER_ERROR)
    ;

    private final String code;
    private final String message;

    @JsonIgnore
    private final HttpStatus status;
}
