package com.ssafy.jjtrip.domain.user.mapper;

import com.ssafy.jjtrip.domain.user.dto.response.UserAndProfileDto;
import com.ssafy.jjtrip.domain.user.entity.Role;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.entity.UserStatus;
import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Optional;

@Mapper
public interface UserMapper {

    @Select("SELECT id, role_id, status_id, email, password_hash, nickname, profile_image_url, created_at, updated_at " +
            "FROM user WHERE email = #{email}")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "role", column = "role_id", javaType = Role.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.RoleTypeHandler.class),
            @Result(property = "status", column = "status_id", javaType = UserStatus.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.UserStatusTypeHandler.class),
            @Result(property = "email", column = "email"),
            @Result(property = "passwordHash", column = "password_hash"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    Optional<User> findByEmail(String email);

    @Select("SELECT id, role_id, status_id, email, password_hash, nickname, profile_image_url, created_at, updated_at " +
            "FROM user WHERE nickname = #{nickname}")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "role", column = "role_id", javaType = Role.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.RoleTypeHandler.class),
            @Result(property = "status", column = "status_id", javaType = UserStatus.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.UserStatusTypeHandler.class),
            @Result(property = "email", column = "email"),
            @Result(property = "passwordHash", column = "password_hash"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    Optional<User> findByNickname(String nickname);

    @Select("SELECT id, role_id, status_id, email, password_hash, nickname, profile_image_url, created_at, updated_at " +
            "FROM user WHERE id = #{id}")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "role", column = "role_id", javaType = Role.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.RoleTypeHandler.class),
            @Result(property = "status", column = "status_id", javaType = UserStatus.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.UserStatusTypeHandler.class),
            @Result(property = "email", column = "email"),
            @Result(property = "passwordHash", column = "password_hash"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    Optional<User> findById(Long id);

    @Select("SELECT COUNT(1) > 0 FROM user WHERE id = #{id}")
    boolean existsById(Long id);

    @Insert("INSERT INTO user (role_id, status_id, email, password_hash, nickname) " +
            "VALUES (#{user.role.id}, #{user.status.id}, #{user.email}, #{user.passwordHash}, #{user.nickname})")
    @Options(useGeneratedKeys = true, keyProperty = "user.id")
    void save(@Param("user") User user);

    @Insert("INSERT INTO user_profile (user_id, friends_count, is_profile_public) VALUES (#{userId}, 0, true)")
    void saveUserProfile(@Param("userId") Long userId);
    
    @Insert("INSERT INTO user_profile (user_id, bio) VALUES (#{userId}, #{bio}) " +
            "ON DUPLICATE KEY UPDATE bio = VALUES(bio)")
    void upsertBio(@Param("userId") Long userId, @Param("bio") String bio);


    @Update("UPDATE user SET password_hash = #{passwordHash} WHERE id = #{userId}")
    void updatePasswordHash(@Param("userId") Long userId, @Param("passwordHash") String passwordHash);

    @Update("UPDATE user SET profile_image_url = #{imageUrl} WHERE id = #{userId}")
    void updateProfileImageUrl(@Param("userId") Long userId, @Param("imageUrl") String imageUrl);

    @Update("UPDATE user SET nickname = #{nickname} WHERE id = #{userId}")
    void updateNickname(@Param("userId") Long userId, @Param("nickname") String nickname);

    @Update("UPDATE user SET profile_image_url = NULL WHERE id = #{userId}")
    void deleteProfileImageUrl(@Param("userId") Long userId);

    @Select("SELECT " +
            "u.id, u.role_id, u.status_id, u.email, u.nickname, u.profile_image_url, " +
            "up.bio, up.intro, up.home_region_id, up.travel_style_summary, up.travel_style_id, up.profile_banner_url, up.is_profile_public, up.friends_count " +
            "FROM user u " +
            "LEFT JOIN user_profile up ON u.id = up.user_id " +
            "WHERE u.id = #{userId}")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "role", column = "role_id", javaType = Role.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.RoleTypeHandler.class),
            @Result(property = "status", column = "status_id", javaType = UserStatus.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.UserStatusTypeHandler.class),
            @Result(property = "email", column = "email"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url"),
            @Result(property = "bio", column = "bio"),
            @Result(property = "intro", column = "intro"),
            @Result(property = "homeRegionId", column = "home_region_id"),
            @Result(property = "travelStyleSummary", column = "travel_style_summary"),
            @Result(property = "travelStyleId", column = "travel_style_id"),
            @Result(property = "profileBannerUrl", column = "profile_banner_url"),
            @Result(property = "isProfilePublic", column = "is_profile_public"),
            @Result(property = "friendsCount", column = "friends_count")
    })
    Optional<UserAndProfileDto> findUserAndProfileById(@Param("userId") Long userId);

    @Select("SELECT " +
            "f.id, f.role_id, f.status_id, f.email, f.nickname, f.profile_image_url, " +
            "fp.bio, fp.intro, fp.home_region_id, fp.travel_style_summary, fp.travel_style_id, fp.profile_banner_url, fp.is_profile_public, fp.friends_count " +
            "FROM friendship fs " +
            "JOIN user f ON (fs.user_id_a = f.id OR fs.user_id_b = f.id) AND f.id != #{userId} " +
            "LEFT JOIN user_profile fp ON f.id = fp.user_id " +
            "WHERE (fs.user_id_a = #{userId} OR fs.user_id_b = #{userId})")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "role", column = "role_id", javaType = Role.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.RoleTypeHandler.class),
            @Result(property = "status", column = "status_id", javaType = UserStatus.class, typeHandler = com.ssafy.jjtrip.domain.user.mapper.UserStatusTypeHandler.class),
            @Result(property = "email", column = "email"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url"),
            @Result(property = "bio", column = "bio"),
            @Result(property = "intro", column = "intro"),
            @Result(property = "homeRegionId", column = "home_region_id"),
            @Result(property = "travelStyleSummary", column = "travel_style_summary"),
            @Result(property = "travelStyleId", column = "travel_style_id"),
            @Result(property = "profileBannerUrl", column = "profile_banner_url"),
            @Result(property = "isProfilePublic", column = "is_profile_public"),
            @Result(property = "friendsCount", column = "friends_count")
    })
    List<UserAndProfileDto> findFriendsByUserId(@Param("userId") Long userId);

    @Update("UPDATE user_profile SET travel_style_summary = #{summary} WHERE user_id = #{userId}")
    void updateTravelStyleSummary(@Param("userId") Long userId, @Param("summary") String summary);

    @Update("UPDATE user_profile up SET friends_count = (" +
            "SELECT COUNT(*) FROM friendship f WHERE f.user_id_a = up.user_id OR f.user_id_b = up.user_id)")
    void syncAllFriendsCounts();

    @Update("UPDATE user_profile SET friends_count = friends_count + 1 WHERE user_id = #{userId}")
    void incrementFriendsCount(@Param("userId") Long userId);

    @Update("UPDATE user_profile SET friends_count = GREATEST(friends_count - 1, 0) WHERE user_id = #{userId}")
    void decrementFriendsCount(@Param("userId") Long userId);



    @Select("SELECT id, nickname, profile_image_url " +
            "FROM user WHERE nickname LIKE CONCAT('%', #{nickname}, '%')")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profile_image_url")
    })
    List<User> findByNicknameContaining(@Param("nickname") String nickname);
}
