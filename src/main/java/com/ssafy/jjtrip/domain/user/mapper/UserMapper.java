package com.ssafy.jjtrip.domain.user.mapper;

import com.ssafy.jjtrip.domain.user.entity.User;
import java.util.Optional;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    Optional<User> findById(Long id);

    void insertUser(User user);
}
