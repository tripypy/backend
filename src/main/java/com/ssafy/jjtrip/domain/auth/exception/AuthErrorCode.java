package com.ssafy.jjtrip.domain.auth.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum AuthErrorCode implements ErrorCode {

    AUTHENTICATION_FAILED("AUTH_001", "인증에 실패했습니다.", HttpStatus.UNAUTHORIZED),
    JWT_TOKEN_EXPIRED("AUTH_002", "토큰이 만료되었습니다.",HttpStatus.UNAUTHORIZED),
    JWT_TOKEN_INVALID("AUTH_003", "유효하지 않은 토큰입니다.", HttpStatus.UNAUTHORIZED),
    DUPLICATE_EMAIL("AUTH_005", "이미 가입된 이메일입니다.", HttpStatus.CONFLICT);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
