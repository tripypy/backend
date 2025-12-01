package com.ssafy.jjtrip.common.security;

import com.ssafy.jjtrip.common.exception.ErrorResponse;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        ErrorResponse.from(AuthErrorCode.AUTHENTICATION_FAILED)
                .writeTo(response);
    }
}
