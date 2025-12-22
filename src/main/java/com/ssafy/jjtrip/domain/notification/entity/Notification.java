package com.ssafy.jjtrip.domain.notification.entity;

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
    private Long targetId;    // TripLog ID, Trip ID, or User ID
    private String targetUrl; // Frontend direct link
    private boolean isRead;
    private LocalDateTime createdAt;
}
