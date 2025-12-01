package com.ssafy.jjtrip.domain.auth.service;

import com.ssafy.jjtrip.common.security.JwtTokenProvider;
import com.ssafy.jjtrip.domain.auth.dto.SignupRequestDto;
import com.ssafy.jjtrip.domain.auth.dto.TokenInfo;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
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

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Transactional
    public TokenInfo login(String email, String password) {
        // 1. 인증 시도
        Authentication authentication = authenticate(email, password);

        // 2. 인증된 Authentication 을 SecurityContext 에 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. 토큰 발급
        return issueTokens(authentication);
    }

    @Transactional
    public void signup(SignupRequestDto signupRequestDto) {
        validateDuplicateEmail(signupRequestDto.email());
        User user = buildNewUser(signupRequestDto);
        userMapper.save(user);
    }

    private Authentication authenticate(String email, String password) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(email, password);
        return authenticationManagerBuilder.getObject().authenticate(authToken);
    }

    private TokenInfo issueTokens(Authentication authentication) {
        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);
        return new TokenInfo(accessToken, refreshToken);
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
