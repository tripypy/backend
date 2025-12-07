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
    REFRESH_TOKEN_NOT_FOUND("AUTH_004", "리프레시 토큰이 없습니다.", HttpStatus.UNAUTHORIZED),
    DUPLICATE_EMAIL("AUTH_005", "이미 가입된 이메일입니다.", HttpStatus.CONFLICT),
    DUPLICATE_NICKNAME("AUTH_006", "이미 사용중인 닉네임입니다.", HttpStatus.CONFLICT),
    INVALID_PASSWORD_FORMAT("AUTH_007", "비밀번호 형식이 올바르지 않습니다.", HttpStatus.BAD_REQUEST),
    USER_NOT_FOUND("AUTH_008", "해당하는 사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
