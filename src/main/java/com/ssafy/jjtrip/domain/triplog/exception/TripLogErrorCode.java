package com.ssafy.jjtrip.domain.triplog.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum TripLogErrorCode implements ErrorCode {

    LOG_NOT_FOUND("TRIPLOG_001", "해당 여행 기록을 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    TRIPLOG_ALREADY_EXISTS("TRIPLOG_002", "이미 여행에 대한 기록이 존재합니다. 하나의 여행에는 하나의 기록만 허용됩니다.", HttpStatus.CONFLICT),
    FORBIDDEN_ACCESS("TRIPLOG_003", "접근 권한이 없습니다.", HttpStatus.FORBIDDEN),
    DATA_INTEGRITY_ERROR("TRIPLOG_004", "데이터 무결성 오류가 발생했습니다. (존재하지 않는 부모 댓글 참조)", HttpStatus.INTERNAL_SERVER_ERROR),
    COMMENT_NOT_FOUND("TRIPLOG_004", "해당 댓글을 찾을 수 없습니다.", HttpStatus.NOT_FOUND);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
