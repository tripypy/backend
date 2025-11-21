package com.ssafy.jjtrip.common.exception;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Getter;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
@Getter
public enum ErrorCode {

	// Common
	INTERNAL_SERVER_ERROR("COMMON_001", "서버 내부 오류가 발생했습니다.", HttpStatus.INTERNAL_SERVER_ERROR),
	INVALID_REQUEST("COMMON_002", "잘못된 요청입니다.", HttpStatus.BAD_REQUEST),
    RESOURCE_NOT_FOUND("COMMON_003", "요청한 리소스를 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    METHOD_NOT_ALLOWED("COMMON_004", "허용되지 않는 메서드입니다.", HttpStatus.METHOD_NOT_ALLOWED),
    HANDLE_ACCESS_DENIED("COMMON_005", "접근이 거부되었습니다.", HttpStatus.FORBIDDEN),
    UNAUTHORIZED("COMMON_006", "인증되지 않은 사용자입니다.", HttpStatus.UNAUTHORIZED),
    TOO_MANY_REQUESTS("COMMON_007", "과도한 요청을 보내셨습니다. 잠시 기다려 주세요.", HttpStatus.TOO_MANY_REQUESTS),
	;

    private final String code;
    private final String message;

    @JsonIgnore
    private final HttpStatus status;

    ErrorCode(String code, String message, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.status = status;
    }
}
