package com.ssafy.jjtrip.domain.user.mapper;

import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import java.util.Optional;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {

    @Select("SELECT id, role_id, status_id, email, password_hash, nickname, profile_image_url, created_at, updated_at " +
            "FROM user WHERE email = #{email}")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "role", column = "role_id", javaType = Role.class),
            @Result(property = "status", column = "status_id", javaType = UserStatus.class),
            @Result(property = "email", column = "email"),
            @Result(property = "passwordHash", column = "password_hash"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    Optional<User> findByEmail(String email);

    @Insert("INSERT INTO user (role_id, status_id, email, password_hash, nickname) " +
            "VALUES (#{role}, #{status}, #{email}, #{passwordHash}, #{nickname})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void save(User user);
}
