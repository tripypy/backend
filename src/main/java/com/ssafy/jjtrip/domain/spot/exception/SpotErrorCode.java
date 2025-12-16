package com.ssafy.jjtrip.domain.spot.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum SpotErrorCode implements ErrorCode {

    SPOT_NOT_FOUND("SPOT_001", "해당 장소를 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    ;

    private final String code;
    private final String message;
    private final HttpStatus status;
}
