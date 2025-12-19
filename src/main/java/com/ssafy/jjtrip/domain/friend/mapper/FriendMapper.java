package com.ssafy.jjtrip.domain.friend.mapper;

import com.ssafy.jjtrip.domain.friend.dto.response.FriendRequestResponseDto;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequest;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequestStatus;
import com.ssafy.jjtrip.domain.friend.entity.Friendship;
import org.apache.ibatis.annotations.*;

import java.util.List;
import java.util.Optional;

@Mapper
public interface FriendMapper {
    // 1. 친구 요청 생성
    @Insert("INSERT INTO friend_request (requester_id, receiver_id, status) " +
            "VALUES (#{requesterId}, #{receiverId}, #{status})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void saveRequest(FriendRequest friendRequest);

    // 2. 친구 요청 상태 변경 (수락, 거절)
    @Update("UPDATE friend_request SET status = #{status} WHERE id = #{requestId}")
    int updateRequestStatus(@Param("requestId") Long requestId, @Param("status") FriendRequestStatus status);

    // 중복 요청 검증용
    @Select("SELECT * FROM friend_request " +
            "WHERE (requester_id = #{requesterId} AND receiver_id = #{receiverId}) OR " +
            "(requester_id = #{receiverId} AND receiver_id = #{requesterId})")
    Optional<FriendRequest> findRequestByUsers(@Param("requesterId") Long requesterId, @Param("receiverId") Long receiverId);

    // 이미 친구인지 검증용
    @Select("SELECT * FROM friendship WHERE user_id_a = #{userIdA} AND user_id_b = #{userIdB}")
    Optional<Friendship> findFriendshipByUsers(@Param("userIdA") Long userIdA, @Param("userIdB") Long userIdB);

    // 3. ID로 친구 요청 조회


    // 4. 받은 친구 요청 목록 조회
    @Select("SELECT fr.id as requestId, fr.status, fr.created_at as createdAt, " +
            "u.id as userId, u.nickname, u.profile_image_url as profileImageUrl " +
            "FROM friend_request fr " +
            "JOIN user u ON fr.requester_id = u.id " +
            "WHERE fr.receiver_id = #{userId} AND fr.status = 'PENDING'")
    @Results({
            @Result(property = "requestId", column = "requestId"),
            @Result(property = "status", column = "status"),
            @Result(property = "createdAt", column = "createdAt"),
            @Result(property = "user.userId", column = "userId"),
            @Result(property = "user.nickname", column = "nickname"),
            @Result(property = "user.profileImageUrl", column = "profileImageUrl")
    })
    List<FriendRequestResponseDto> findReceivedRequestsByUserId(@Param("userId") Long userId);


    // 5. 보낸 친구 요청 목록 조회
    @Select("SELECT fr.id as requestId, fr.status, fr.created_at as createdAt, " +
            "u.id as userId, u.nickname, u.profile_image_url as profileImageUrl " +
            "FROM friend_request fr " +
            "JOIN user u ON fr.receiver_id = u.id " +
            "WHERE fr.requester_id = #{userId}")
    @Results({
            @Result(property = "requestId", column = "requestId"),
            @Result(property = "status", column = "status"),
            @Result(property = "createdAt", column = "createdAt"),
            @Result(property = "user.userId", column = "userId"),
            @Result(property = "user.nickname", column = "nickname"),
            @Result(property = "user.profileImageUrl", column = "profileImageUrl")
    })
    List<FriendRequestResponseDto> findSentRequestsByUserId(@Param("userId") Long userId);
    
    // 6. 친구 요청 삭제
    // 7. 친구 관계 생성
    // 8. 친구 관계 삭제
    // 9. 친구 목록 조회
    // 10. 친구 피드 목록 조회
}
