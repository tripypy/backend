package com.ssafy.jjtrip.domain.user.entity;

import com.ssafy.jjtrip.domain.user.exception.UserErrorCode;
import com.ssafy.jjtrip.domain.user.exception.UserException;
import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

    USER(1L, "USER", "일반 사용자"),
    ADMIN(2L, "ADMIN", "관리자");

    private final Long id;
    private final String code;
    private final String name;

    public static Role fromId(Long id) {
        return Arrays.stream(Role.values())
                .filter(role -> role.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new UserException(UserErrorCode.INVALID_ROLE_ID));
    }
}
