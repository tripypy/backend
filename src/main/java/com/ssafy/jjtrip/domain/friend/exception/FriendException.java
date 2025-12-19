package com.ssafy.jjtrip.domain.friend.exception;

import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.ErrorCode;

public class FriendException extends BusinessException {
    public FriendException(ErrorCode errorCode) {
        super(errorCode);
    }
}
