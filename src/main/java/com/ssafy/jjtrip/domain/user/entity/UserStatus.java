package com.ssafy.jjtrip.domain.user.entity;

import com.ssafy.jjtrip.domain.user.exception.UserErrorCode;
import com.ssafy.jjtrip.domain.user.exception.UserException;
import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserStatus {

    ACTIVE(1L, "ACTIVE", "활성", "정상 사용 가능한 계정"),
    DELETE(2L, "DELETED", "탈퇴", "탈퇴한 계정 (로그인 불가)");

    private final Long id;
    private final String code;
    private final String name;
    private final String description;

    public static UserStatus fromId(Long id) {
        return Arrays.stream(UserStatus.values())
                .filter(status -> status.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new UserException(UserErrorCode.INVALID_USER_STATUS_ID));
    }
}
