package com.ssafy.jjtrip.common.s3.exception;

import com.ssafy.jjtrip.common.exception.BusinessException;
import com.ssafy.jjtrip.common.exception.ErrorCode;

public class FileException extends BusinessException {

    public FileException(ErrorCode errorCode) {
        super(errorCode);
    }
}
