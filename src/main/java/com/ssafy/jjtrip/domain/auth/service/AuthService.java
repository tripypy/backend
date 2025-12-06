package com.ssafy.jjtrip.domain.auth.service;

import com.ssafy.jjtrip.common.mail.EmailService;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.common.security.JwtTokenProvider;
import com.ssafy.jjtrip.common.util.RedisUtil;
import com.ssafy.jjtrip.common.util.EmailMasker;
import com.ssafy.jjtrip.domain.auth.dto.SignupRequestDto;
import com.ssafy.jjtrip.domain.auth.dto.TokenInfo;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import java.security.SecureRandom;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private static final String REDIS_REFRESH_TOKEN_PREFIX = "RefreshToken:";
    private static final String REDIS_BLACKLIST_PREFIX = "BlackList:";
    private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final RedisUtil redisUtil;
    private final EmailService emailService;

    @Value("${app.jwt.refresh-token-expire-time}")
    private long refreshTokenExpireTimeMs;

    @Value("${app.jwt.access-token-expire-time}")
    private long accessTokenExpireTimeMs;

    @Transactional
    public TokenInfo login(String email, String password) {
        Authentication authentication = authenticate(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        TokenInfo tokenInfo = issueTokens(authentication);
        redisUtil.set(REDIS_REFRESH_TOKEN_PREFIX + email, tokenInfo.refreshToken(), refreshTokenExpireTimeMs);
        return tokenInfo;
    }

    @Transactional
    public void logout(String accessToken) {
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        String email = authentication.getName();

        if (redisUtil.hasKey(REDIS_REFRESH_TOKEN_PREFIX + email)) {
            redisUtil.delete(REDIS_REFRESH_TOKEN_PREFIX + email);
        }

        long expiration = jwtTokenProvider.getRemainingExpireTime(accessToken);
        if (expiration > 0) {
            redisUtil.set(REDIS_BLACKLIST_PREFIX + accessToken, "logout", expiration);
        }
    }

    @Transactional
    public void signup(SignupRequestDto signupRequestDto) {
        validatePassword(signupRequestDto.password());
        validateDuplicateEmail(signupRequestDto.email());
        validateDuplicateNickname(signupRequestDto.nickname());
        User user = buildNewUser(signupRequestDto);
        userMapper.save(user);
    }

    @Transactional
    public void resetPassword(String email) {
        userMapper.findByEmail(email).ifPresent(user -> {
            String temporaryPassword = generateTemporaryPassword();
            String encodedPassword = passwordEncoder.encode(temporaryPassword);
            userMapper.updatePasswordHash(user.getId(), encodedPassword);
            emailService.sendNewPasswordEmail(user.getEmail(), temporaryPassword);
        });
    }

    public String findEmailByNickname(String nickname) {
        User user = userMapper.findByNickname(nickname)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));
        return EmailMasker.maskEmail(user.getEmail());
    }

    @Transactional
    public TokenInfo refresh(String refreshToken) {
        jwtTokenProvider.validateToken(refreshToken);

        String email = jwtTokenProvider.getSubject(refreshToken);
        String savedToken = redisUtil.get(REDIS_REFRESH_TOKEN_PREFIX + email);
        if (savedToken == null || !savedToken.equals(refreshToken)) {
            throw new AuthException(AuthErrorCode.JWT_TOKEN_INVALID);
        }

        User user = userMapper.findByEmail(email)
                .orElseThrow(() -> new AuthException(AuthErrorCode.JWT_TOKEN_INVALID));

        CustomUserDetails userDetails = new CustomUserDetails(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());

        TokenInfo newTokenInfo = issueTokens(authentication);
        redisUtil.set(REDIS_REFRESH_TOKEN_PREFIX + email, newTokenInfo.refreshToken(), refreshTokenExpireTimeMs);
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

    private void validatePassword(String password) {
        if (!Pattern.matches(PASSWORD_PATTERN, password)) {
            throw new AuthException(AuthErrorCode.INVALID_PASSWORD_FORMAT);
        }
    }

    private void validateDuplicateEmail(String email) {
        userMapper.findByEmail(email).ifPresent(user -> {
            throw new AuthException(AuthErrorCode.DUPLICATE_EMAIL);
        });
    }

    private void validateDuplicateNickname(String nickname) {
        userMapper.findByNickname(nickname).ifPresent(user -> {
            throw new AuthException(AuthErrorCode.DUPLICATE_NICKNAME);
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

    private String generateTemporaryPassword() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(10);
        for (int i = 0; i < 10; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
