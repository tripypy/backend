package com.ssafy.jjtrip.common.s3.exception;

import com.ssafy.jjtrip.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum FileErrorCode implements ErrorCode {

    FILE_UPLOAD_FAILED("FILE_001", "File upload failed.", HttpStatus.INTERNAL_SERVER_ERROR),
    EMPTY_FILE("FILE_002", "File is empty.", HttpStatus.BAD_REQUEST),
    INVALID_FILE_EXTENSION("FILE_003", "Invalid file extension.", HttpStatus.BAD_REQUEST);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
