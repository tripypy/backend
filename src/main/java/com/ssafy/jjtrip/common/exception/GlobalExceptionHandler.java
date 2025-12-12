package com.ssafy.jjtrip.common.exception;

import com.ssafy.jjtrip.common.exception.ErrorResponse.InvalidParam;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

	@ExceptionHandler(BusinessException.class)
	public ResponseEntity<Object> handleBusinessException(BusinessException ex) {
		return ErrorResponse.from(ex.getErrorCode()).toResponseEntity();
	}
	
	@Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {
        List<InvalidParam> invalidParams = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(ErrorResponse.InvalidParam::from)
                .toList();

        return ErrorResponse.of(CommonErrorCode.INVALID_REQUEST, invalidParams).toResponseEntity();
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        return ErrorResponse.from(CommonErrorCode.INVALID_REQUEST).toResponseEntity();
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Object> handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex) {
        String reason = String.format(
                "입력값 '%s'는 %s 타입이어야 합니다.",
                ex.getValue(),
                ex.getRequiredType().getSimpleName()
        );
        List<InvalidParam> invalidParams = List.of(new InvalidParam(ex.getName(), reason));
        return ErrorResponse.of(CommonErrorCode.INVALID_REQUEST, invalidParams).toResponseEntity();
    }

	@ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Object> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ErrorResponse.from(CommonErrorCode.INVALID_REQUEST).toResponseEntity();
    }
	
	@ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGenericException(Exception ex) {
        return ErrorResponse.from(CommonErrorCode.INTERNAL_SERVER_ERROR).toResponseEntity();
    }
}
