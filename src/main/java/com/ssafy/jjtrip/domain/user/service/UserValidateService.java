package com.ssafy.jjtrip.domain.user.service;

import com.ssafy.jjtrip.domain.user.exception.UserErrorCode;
import com.ssafy.jjtrip.domain.user.exception.UserException;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserValidateService {

    private final UserMapper userMapper;

    public void validateUserExists(Long userId) {
        if (!userMapper.existsById(userId)) {
            throw new UserException(UserErrorCode.USER_NOT_FOUND);
        }
    }
}
