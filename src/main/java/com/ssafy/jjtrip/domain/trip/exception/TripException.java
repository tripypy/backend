package com.ssafy.jjtrip.domain.trip.exception;

import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.ErrorCode;

public class TripException extends BusinessException {

    public TripException(ErrorCode errorCode) {
        super(errorCode);
    }
}
