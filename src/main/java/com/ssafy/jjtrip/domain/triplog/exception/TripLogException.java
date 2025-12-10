package com.ssafy.jjtrip.domain.triplog.exception;

import com.ssafy.jjtrip.common.exception.BusinessException;

public class TripLogException extends BusinessException {

    public TripLogException(TripLogErrorCode errorCode) {
        super(errorCode);
    }
}
