package com.ssafy.jjtrip.domain.triplog.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum TripLogErrorCode implements ErrorCode {

    LOG_NOT_FOUND("TRIPLOG_001", "해당 여행 기록을 찾을 수 없습니다.", HttpStatus.NOT_FOUND);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
