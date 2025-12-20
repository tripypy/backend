package com.ssafy.jjtrip.domain.friend.mapper;

import com.ssafy.jjtrip.domain.friend.dto.response.FriendRequestResponseDto;
import com.ssafy.jjtrip.domain.friend.dto.response.SimpleUserInfoDto;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequest;
import com.ssafy.jjtrip.domain.friend.entity.Friendship;
import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Optional;

@Mapper
public interface FriendMapper {
    // 1. 친구 요청 생성
    @Insert("INSERT INTO friend_request (requester_id, receiver_id) " +
            "VALUES (#{requesterId}, #{receiverId})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void saveRequest(FriendRequest friendRequest);

    // 중복 요청 검증용
    @Select("SELECT * FROM friend_request " +
            "WHERE (requester_id = #{requesterId} AND receiver_id = #{receiverId}) OR " +
            "(requester_id = #{receiverId} AND receiver_id = #{requesterId})")
    Optional<FriendRequest> findRequestByUsers(@Param("requesterId") Long requesterId, @Param("receiverId") Long receiverId);

    // 이미 친구인지 검증용
    @Select("SELECT * FROM friendship WHERE user_id_a = #{userIdA} AND user_id_b = #{userIdB}")
    Optional<Friendship> findFriendshipByUsers(@Param("userIdA") Long userIdA, @Param("userIdB") Long userIdB);

    // 3. ID로 친구 요청 조회
    @Select("SELECT id, requester_id, receiver_id, created_at FROM friend_request WHERE id = #{requestId}")
    Optional<FriendRequest> findRequestById(@Param("requestId") Long requestId);

    // 4. 받은 친구 요청 목록 조회
    @Select("SELECT fr.id as requestId, fr.created_at as createdAt, " +
            "u.id as userId, u.nickname, u.profile_image_url as profileImageUrl " +
            "FROM friend_request fr " +
            "JOIN user u ON fr.requester_id = u.id " +
            "WHERE fr.receiver_id = #{userId}")
    @Results({
            @Result(property = "requestId", column = "requestId"),
            @Result(property = "createdAt", column = "createdAt"),
            @Result(property = "user.userId", column = "userId"),
            @Result(property = "user.nickname", column = "nickname"),
            @Result(property = "user.profileImageUrl", column = "profileImageUrl")
    })
    List<FriendRequestResponseDto> findReceivedRequestsByUserId(@Param("userId") Long userId);


    // 5. 보낸 친구 요청 목록 조회
    @Select("SELECT fr.id as requestId, fr.created_at as createdAt, " +
            "u.id as userId, u.nickname, u.profile_image_url as profileImageUrl " +
            "FROM friend_request fr " +
            "JOIN user u ON fr.receiver_id = u.id " +
            "WHERE fr.requester_id = #{userId}")
    @Results({
            @Result(property = "requestId", column = "requestId"),
            @Result(property = "createdAt", column = "createdAt"),
            @Result(property = "user.userId", column = "userId"),
            @Result(property = "user.nickname", column = "nickname"),
            @Result(property = "user.profileImageUrl", column = "profileImageUrl")
    })
    List<FriendRequestResponseDto> findSentRequestsByUserId(@Param("userId") Long userId);

    // 6. 친구 요청 삭제
    @Delete("DELETE FROM friend_request WHERE id = #{requestId}")
    int deleteRequestById(@Param("requestId") Long requestId);
    
    // 7. 친구 관계 생성
    @Insert("INSERT INTO friendship (user_id_a, user_id_b) VALUES (#{userIdA}, #{userIdB})")
    void saveFriendship(Friendship friendship);

    // 8. 친구 관계 삭제
    @Delete("DELETE FROM friendship WHERE (user_id_a = #{userId1} AND user_id_b = #{userId2}) OR (user_id_a = #{userId2} AND user_id_b = #{userId1})")
    int deleteFriendship(@Param("userId1") Long userId1, @Param("userId2") Long userId2);


    // 9. 친구 목록 조회
    @Select("SELECT u.id AS userId, u.nickname, u.profile_image_url AS profileImageUrl " +
            "FROM friendship f " +
            "JOIN user u ON (f.user_id_a = #{userId} AND u.id = f.user_id_b) OR (f.user_id_b = #{userId} AND u.id = f.user_id_a) " +
            "WHERE f.user_id_a = #{userId} OR f.user_id_b = #{userId}")
    @Results({
            @Result(property = "userId", column = "userId"),
            @Result(property = "nickname", column = "nickname"),
            @Result(property = "profileImageUrl", column = "profileImageUrl")
    })
    List<SimpleUserInfoDto> findFriendsByUserId(@Param("userId") Long userId);

    // 10. 친구 피드 목록 조회
}