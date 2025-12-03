package com.ssafy.jjtrip.domain.auth.controller;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.auth.dto.*;
import com.ssafy.jjtrip.domain.auth.service.AuthService;
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
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Value("${app.jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTimeMs;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto request) {
        TokenInfo tokenInfo = authService.login(request.email(), request.password());
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();

        LoginResponseDto body = new LoginResponseDto(
                tokenInfo.accessToken(),
                tokenInfo.accessTokenExpiresIn(),
                user.getUsername(),
                user.getNickname()
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, createRefreshTokenCookie(tokenInfo.refreshToken()).toString())
                .body(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String accessToken) {
        String token = resolveToken(accessToken);
        authService.logout(token);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .maxAge(0)
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
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
                .maxAge(Duration.ofMillis(refreshTokenExpireTimeMs))
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token이 없습니다.");
        }

        TokenInfo tokenInfo = authService.refresh(refreshToken);

        TokenResponseDto body = new TokenResponseDto(
                tokenInfo.accessToken(),
                tokenInfo.accessTokenExpiresIn()
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, createRefreshTokenCookie(tokenInfo.refreshToken()).toString())
                .body(body);
    }

    private String resolveToken(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}