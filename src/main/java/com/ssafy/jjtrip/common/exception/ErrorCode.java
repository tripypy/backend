package com.ssafy.jjtrip.common.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.http.HttpStatus;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public interface ErrorCode {

    String getCode();

    String getMessage();

    @JsonIgnore
    HttpStatus getStatus();
}
