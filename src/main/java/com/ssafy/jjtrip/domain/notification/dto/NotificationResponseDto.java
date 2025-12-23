package com.ssafy.jjtrip.domain.notification.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ssafy.jjtrip.domain.notification.entity.Notification;
import com.ssafy.jjtrip.domain.notification.entity.NotificationType;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class NotificationResponseDto {
    private Long id;
    private Long senderId;
    private String senderNickname;
    private String senderProfileImageUrl;
    private NotificationType type;
    private String message;
    private Long targetId;
    private String targetUrl;
    
    @JsonProperty("isRead")
    private boolean isRead;
    
    private LocalDateTime createdAt;

    public static NotificationResponseDto from(Notification notification, String senderNickname, String senderProfileImageUrl) {
        return NotificationResponseDto.builder()
                .id(notification.getId())
                .senderId(notification.getSenderId())
                .senderNickname(senderNickname)
                .senderProfileImageUrl(senderProfileImageUrl)
                .type(notification.getType())
                .message(notification.getMessage())
                .targetId(notification.getTargetId())
                .targetUrl(notification.getTargetUrl())
                .isRead(notification.isRead())
                .createdAt(notification.getCreatedAt())
                .build();
    }
}
