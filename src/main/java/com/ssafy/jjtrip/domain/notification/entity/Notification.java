package com.ssafy.jjtrip.domain.notification.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Notification {
    private Long id;
    private Long receiverId;
    private Long senderId;
    private NotificationType type;
    private String message;
    private Long targetId;
    private String targetUrl;
    
    @JsonProperty("isRead")
    private boolean isRead;
    
    private LocalDateTime createdAt;
}
