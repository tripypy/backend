package com.ssafy.jjtrip.domain.friend.mapper;

import com.ssafy.jjtrip.domain.friend.entity.FriendRequest;
import com.ssafy.jjtrip.domain.friend.entity.FriendRequestStatus;
import com.ssafy.jjtrip.domain.friend.entity.Friendship;
import org.apache.ibatis.annotations.*;

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
    // 5. 보낸 친구 요청 목록 조회
    // 6. 친구 요청 삭제
    // 7. 친구 관계 생성
    // 8. 친구 관계 삭제
    // 9. 친구 목록 조회
    // 10. 친구 피드 목록 조회
}
