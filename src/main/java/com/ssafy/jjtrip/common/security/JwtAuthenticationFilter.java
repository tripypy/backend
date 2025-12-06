package com.ssafy.jjtrip.common.security;

import com.ssafy.jjtrip.common.util.RedisUtil;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisUtil redisUtil;

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String BLACKLIST_PREFIX = "BlackList:";
    private static final String LOGOUT_URL = "/api/auth/logout";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = resolveToken(request);

        if (StringUtils.hasText(token)) {
            try {
                authenticate(token);
            } catch (AuthException e) {
                handleAuthException(request, e);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void authenticate(String token) {
        jwtTokenProvider.validateToken(token);

        if (redisUtil.hasKey(BLACKLIST_PREFIX + token)) {
            throw new AuthException(AuthErrorCode.JWT_TOKEN_INVALID);
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void handleAuthException(HttpServletRequest request, AuthException e) {
        boolean isTokenExpired = e.getErrorCode() == AuthErrorCode.JWT_TOKEN_EXPIRED;
        boolean isLogoutRequest = isLogoutRequest(request);

        if (!isTokenExpired || !isLogoutRequest) {
            throw e;
        }

        log.debug("만료된 Access Token으로 들어온 로그아웃 요청이 감지되었습니다. 검증 절차를 스킵합니다. URI: {}", request.getRequestURI());
    }

    private boolean isLogoutRequest(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals(LOGOUT_URL) || path.equals(LOGOUT_URL + "/");
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}