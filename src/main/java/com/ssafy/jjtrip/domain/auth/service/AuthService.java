package com.ssafy.jjtrip.domain.auth.service;

import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.common.security.JwtTokenProvider;
import com.ssafy.jjtrip.common.util.RedisUtil;
import com.ssafy.jjtrip.domain.auth.dto.SignupRequestDto;
import com.ssafy.jjtrip.domain.auth.dto.TokenInfo;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final RedisUtil redisUtil;

    @Value("${app.jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTimeMs;

    @Value("${app.jwt.access-token-expire-time}")
    private long accessTokenExpireTimeMs;

    @Transactional
    public TokenInfo login(String email, String password) {
        Authentication authentication = authenticate(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        TokenInfo tokenInfo = issueTokens(authentication);
        redisUtil.set("RefreshToken:" + email, tokenInfo.refreshToken(), refreshTokenExpireTimeMs);

        return tokenInfo;
    }

    @Transactional
    public void logout(String accessToken) {
        jwtTokenProvider.validateToken(accessToken);

        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        String email = authentication.getName();

        if (redisUtil.hasKey("RefreshToken:" + email)) {
            redisUtil.delete("RefreshToken:" + email);
        }

        long expiration = jwtTokenProvider.getRemainingExpireTime(accessToken);
        if (expiration > 0) {
            redisUtil.setBlackList("BlackList:" + accessToken, "logout", expiration);
        }
    }

    @Transactional
    public void signup(SignupRequestDto signupRequestDto) {
        validateDuplicateEmail(signupRequestDto.email());
        User user = buildNewUser(signupRequestDto);
        userMapper.save(user);
    }

    @Transactional
    public TokenInfo refresh(String refreshToken) {
        jwtTokenProvider.validateToken(refreshToken);

        String email = jwtTokenProvider.getSubject(refreshToken);
        String savedToken = redisUtil.get("RefreshToken:" + email);
        if (savedToken == null || !savedToken.equals(refreshToken)) {
            throw new AuthException(AuthErrorCode.JWT_TOKEN_INVALID);
        }

        User user = userMapper.findByEmail(email)
                .orElseThrow(() -> new AuthException(AuthErrorCode.JWT_TOKEN_INVALID));

        CustomUserDetails userDetails = new CustomUserDetails(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());

        TokenInfo newTokenInfo = issueTokens(authentication);
        redisUtil.set("RefreshToken:" + email, newTokenInfo.refreshToken(), refreshTokenExpireTimeMs);

        return newTokenInfo;
    }

    private Authentication authenticate(String email, String password) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(email, password);
        return authenticationManager.authenticate(authToken);
    }

    private TokenInfo issueTokens(Authentication authentication) {
        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);

        return new TokenInfo(accessToken, refreshToken, accessTokenExpireTimeMs);
    }

    private void validateDuplicateEmail(String email) {
        userMapper.findByEmail(email).ifPresent(user -> {
            throw new AuthException(AuthErrorCode.DUPLICATE_EMAIL);
        });
    }

    private User buildNewUser(SignupRequestDto dto) {
        String encodedPassword = passwordEncoder.encode(dto.password());
        return User.builder()
                .email(dto.email())
                .passwordHash(encodedPassword)
                .nickname(dto.nickname())
                .role(Role.USER)
                .status(UserStatus.ACTIVE)
                .build();
    }
}