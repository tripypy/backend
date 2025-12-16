package com.ssafy.jjtrip.domain.spot.exception;

import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.ErrorCode;

public class SpotException extends BusinessException {

    public SpotException(ErrorCode errorCode) {
        super(errorCode);
    }
}
