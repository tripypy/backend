package com.ssafy.jjtrip.domain.trip.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum TripErrorCode implements ErrorCode {

    TRIP_NOT_FOUND("TRIP_001", "해당 여행을 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    FORBIDDEN_TRIP_ACCESS("TRIP_002", "해당 여행에 대한 접근 권한이 없습니다.", HttpStatus.FORBIDDEN),
    ITEM_POSITION_ALREADY_EXISTS("TRIP_003", "이미 해당 순서에 다른 아이템이 존재합니다.", HttpStatus.CONFLICT);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
