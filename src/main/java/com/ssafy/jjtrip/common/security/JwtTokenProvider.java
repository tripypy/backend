package com.ssafy.jjtrip.common.security;

import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.auth.service.CustomUserDetailsService;
import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import java.security.Key;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtTokenProvider {

    private final Key key;
    private final long accessTokenExpireTime;
    private final long refreshTokenExpireTime;

    public JwtTokenProvider(@Value("${app.jwt.secret}") String secretKey,
                            @Value("${app.jwt.access-token-expire-time}") long accessTokenExpireTime,
                            @Value("${app.jwt.refresh-token-expire-time}") long refreshTokenExpireTime) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.refreshTokenExpireTime = refreshTokenExpireTime;
    }

    public String generateAccessToken(Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = userDetails.getUser();

        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("id", user.getId())
                .claim("nickname", user.getNickname())
                .claim("role", user.getRole().name())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + accessTokenExpireTime))
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + refreshTokenExpireTime))
                .signWith(key)
                .compact();
    }

    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get("role") == null) {
            throw new AuthException(AuthErrorCode.JWT_TOKEN_INVALID);
        }

        String email = claims.getSubject();
        Long userId = claims.get("id", Long.class);
        String nickname = claims.get("nickname", String.class);
        String roleStr = claims.get("role", String.class);
        Role role = Role.valueOf(roleStr); // String -> Enum 변환

        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.name()));

        User principalUser = User.builder()
                .id(userId)
                .email(email)
                .nickname(nickname)
                .role(role)
                .status(UserStatus.ACTIVE)
                .build();

        CustomUserDetails principal = new CustomUserDetails(principalUser);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public void validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        } catch (SecurityException | MalformedJwtException
                | UnsupportedJwtException | IllegalArgumentException e) {
            log.info("Invalid JWT Token", e);
            throw new AuthException(AuthErrorCode.JWT_TOKEN_INVALID);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
            throw new AuthException(AuthErrorCode.JWT_TOKEN_EXPIRED);
        }
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public long getRemainingExpireTime(String token) {
        Date expiration = parseClaims(token).getExpiration();
        long now = new Date().getTime();
        return expiration.getTime() - now;
    }

    public String getSubject(String token) {
        return parseClaims(token).getSubject();
    }
}
