package com.ssafy.jjtrip.domain.spot.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum SpotErrorCode implements ErrorCode {

    SPOT_NOT_FOUND("SPOT_001", "해당 장소를 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    REVIEW_NOT_FOUND("SPOT_002", "해당 리뷰를 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    FORBIDDEN_ACCESS("SPOT_003", "접근 권한이 없습니다.", HttpStatus.FORBIDDEN),
    ;

    private final String code;
    private final String message;
    private final HttpStatus status;
}
