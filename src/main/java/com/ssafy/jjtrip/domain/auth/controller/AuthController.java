package com.ssafy.jjtrip.domain.auth.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.auth.dto.LoginRequestDto;
import com.ssafy.jjtrip.domain.auth.dto.LoginResponseDto;
import com.ssafy.jjtrip.domain.auth.dto.SignupRequestDto;
import com.ssafy.jjtrip.domain.auth.dto.TokenInfo;
import com.ssafy.jjtrip.domain.auth.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Value("${app.jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTimeMs;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto request, HttpServletResponse response) {
        TokenInfo tokenInfo = authService.login(request.email(), request.password());
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();

        LoginResponseDto body = new LoginResponseDto(
                tokenInfo.accessToken(),
                user.getUsername(),
                user.getNickname()
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, createRefreshTokenCookie(tokenInfo.refreshToken()).toString())
                .body(body);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequestDto request) {
        authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .maxAge(Duration.ofMillis(refreshTokenExpireTimeMs)) // ms → Duration
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .build();
    }
}
