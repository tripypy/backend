package com.ssafy.jjtrip.domain.auth.controller;

import static com.ssafy.jjtrip.common.security.JwtAuthenticationFilter.AUTHORIZATION_HEADER;
import static com.ssafy.jjtrip.common.security.JwtAuthenticationFilter.BEARER_PREFIX;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.auth.dto.*;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
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

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

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
    public ResponseEntity<?> logout(@RequestHeader(AUTHORIZATION_HEADER) String accessToken) {
        String token = resolveToken(accessToken);
        authService.logout(token);

        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
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

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody PasswordResetRequestDto request) {
        authService.resetPassword(request.email());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/find-email/{nickname}")
    public ResponseEntity<?> findEmailByNickname(@PathVariable("nickname") String nickname) {
        String email = authService.findEmailByNickname(nickname);
        return ResponseEntity.ok(java.util.Map.of("email", email));
    }

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                .maxAge(Duration.ofMillis(refreshTokenExpireTimeMs))
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = REFRESH_TOKEN_COOKIE_NAME, required = false) String refreshToken) {
        if (refreshToken == null) {
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_NOT_FOUND);
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
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}