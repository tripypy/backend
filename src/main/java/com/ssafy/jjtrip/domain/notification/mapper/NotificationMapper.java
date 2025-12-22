package com.ssafy.jjtrip.domain.notification.mapper;

import com.ssafy.jjtrip.domain.notification.entity.Notification;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface NotificationMapper {

    @Insert("INSERT INTO notification (receiver_id, sender_id, type, message, target_id, target_url, is_read, created_at) " +
            "VALUES (#{receiverId}, #{senderId}, #{type}, #{message}, #{targetId}, #{targetUrl}, #{isRead}, NOW())")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void save(Notification notification);

    @Select("SELECT * FROM notification WHERE receiver_id = #{userId} ORDER BY created_at DESC")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "receiverId", column = "receiver_id"),
            @Result(property = "senderId", column = "sender_id"),
            @Result(property = "type", column = "type", typeHandler = com.ssafy.jjtrip.domain.notification.mapper.NotificationTypeHandler.class),
            @Result(property = "message", column = "message"),
            @Result(property = "targetId", column = "target_id"),
            @Result(property = "targetUrl", column = "target_url"),
            @Result(property = "isRead", column = "is_read"),
            @Result(property = "createdAt", column = "created_at")
    })
    List<Notification> findAllByUserId(@Param("userId") Long userId);

    @Select("SELECT COUNT(*) FROM notification WHERE receiver_id = #{userId} AND is_read = false")
    long countUnreadNotifications(@Param("userId") Long userId);

    @Update("UPDATE notification SET is_read = true WHERE id = #{id}")
    void markAsRead(@Param("id") Long id);

    @Update("UPDATE notification SET is_read = true WHERE receiver_id = #{userId}")
    void markAllAsRead(@Param("userId") Long userId);
    
    @Delete("DELETE FROM notification WHERE id = #{id}")
    void deleteById(@Param("id") Long id);
}
