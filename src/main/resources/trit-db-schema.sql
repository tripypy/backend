-- =================================================================
-- 데이터베이스 설정
-- =================================================================
DROP DATABASE IF EXISTS trit_dev;
CREATE DATABASE trit_dev DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE trit_dev;

-- =================================================================
-- 1. 사용자 및 권한
-- =================================================================

-- 역할 (Role)
CREATE TABLE `role` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'USER', 'ADMIN'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 상태 (User Status)
CREATE TABLE `user_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) NOT NULL UNIQUE, -- 'ACTIVE', 'DELETED'
  `name`        VARCHAR(50) NOT NULL,
  `description` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 (User)
CREATE TABLE `user` (
  `id`                BIGINT NOT NULL AUTO_INCREMENT,
  `role_id`           BIGINT NOT NULL,
  `status_id`         BIGINT NOT NULL,
  `email`             VARCHAR(100) NOT NULL UNIQUE,
  `password_hash`     VARCHAR(255) NOT NULL,
  `nickname`          VARCHAR(50) NOT NULL,
  `profile_image_url` VARCHAR(255),
  `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_email` (`email`),
  CONSTRAINT `fk_user_role` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `fk_user_status` FOREIGN KEY (`status_id`) REFERENCES `user_status` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 프로필 (User Profile)
CREATE TABLE `user_profile` (
  `user_id`                 BIGINT NOT NULL,
  `bio`                     VARCHAR(255),
  `intro`                   TEXT,
  `home_region_id`          BIGINT,
  `travel_style_summary`    TEXT,
  `travel_style_id`         BIGINT,
  `profile_banner_url`      VARCHAR(255),
  `is_profile_public`       BOOLEAN NOT NULL DEFAULT TRUE,
  `friends_count`           INT NOT NULL DEFAULT 0, -- Added friends_count column
  `created_at`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  CONSTRAINT `fk_user_profile_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 친구 관계 (Friendship)
CREATE TABLE `friendship` (
  `user_id_a`  BIGINT NOT NULL,
  `user_id_b`  BIGINT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id_a`, `user_id_b`),
  CONSTRAINT `fk_friendship_user_a` FOREIGN KEY (`user_id_a`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_friendship_user_b` FOREIGN KEY (`user_id_b`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_friendship_order` CHECK (`user_id_a` < `user_id_b`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==========================================
-- 🏢 2. 장소 (Spot Domain)
-- ==========================================

-- 장소 (Spot)
CREATE TABLE `spot` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `kakao_place_id`  VARCHAR(50) NOT NULL,
  `name`            VARCHAR(100) NOT NULL,
  `address`         VARCHAR(255),
  `category`        VARCHAR(50),
  `lat`             DECIMAL(10, 8) NOT NULL,
  `lng`             DECIMAL(11, 8) NOT NULL,
  `place_url`       VARCHAR(255),
  `thumbnail_url`   VARCHAR(255),
  `review_count`    INT DEFAULT 0,
  `average_rating`  DECIMAL(3, 2) DEFAULT 0.0,
  `created_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_kakao_place_id` (`kakao_place_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==========================================
-- ✈️ 3. 여행 계획 (Trip Domain)
-- ==========================================

-- 여행 상태 마스터 (Trip Status)
CREATE TABLE `trip_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) NOT NULL UNIQUE, -- 'DRAFT', 'PLANNED', 'COMPLETED'
  `name`        VARCHAR(50) NOT NULL,        -- '작성 중', '계획 완료', '여행 완료'
  `description` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 (Trip)
CREATE TABLE `trip` (
  `id`             BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`        BIGINT NOT NULL,
  `trip_status_id` BIGINT NOT NULL,
  `title`          VARCHAR(100) NOT NULL,
  `start_date`     DATE,
  `end_date`       DATE,
  `visibility`     VARCHAR(20) NOT NULL DEFAULT 'PRIVATE' COMMENT "'PUBLIC' 또는 'PRIVATE'",
  `created_at`     DATETIME DEFAULT NOW(),
  `updated_at`     DATETIME,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_trip_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_trip_status` FOREIGN KEY (`trip_status_id`) REFERENCES `trip_status` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 상세 아이템 (Trip Item)
CREATE TABLE `trip_item` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `trip_id`     BIGINT NOT NULL,
  `spot_id`     BIGINT NOT NULL,
  `day_number`  INT NOT NULL,              -- 1일차, 2일차...
  `order_index` INT NOT NULL,              -- 방문 순서
  `memo`        TEXT,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),

  INDEX `idx_trip_day_order` (`trip_id`, `day_number`, `order_index`),
  UNIQUE KEY `uk_trip_day_order` (`trip_id`, `day_number`, `order_index`),

  CONSTRAINT `fk_item_trip` FOREIGN KEY (`trip_id`) REFERENCES `trip` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_item_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ==========================================
-- ✍️ 4. 여행 기록 (Trip Log Domain)
-- ==========================================

-- 여행 기록 (Trip Log)
CREATE TABLE `trip_log` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `trip_id`          BIGINT NOT NULL,
  `title`            VARCHAR(255) NOT NULL,
  `content`          TEXT COMMENT '마크다운 형식 본문. 이미지는 {{img_key}} 형태의 참조 키 사용',
  `location_summary` VARCHAR(255) COMMENT '장소 요약 (예: 서울시 or 서울시 강남구 or 서울시 강남구 역삼동)',
  `created_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_trip_log_trip_id` (`trip_id`), -- trip과 1:1 관계를 위해 UNIQUE 제약조건 추가
  CONSTRAINT `fk_trip_log_trip` FOREIGN KEY (`trip_id`) REFERENCES `trip` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 기록 좋아요 (Log Like)
CREATE TABLE `log_like` (
    `user_id`    BIGINT NOT NULL,
    `log_id`     BIGINT NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`user_id`, `log_id`), -- 한 사용자가 한 게시물에 좋아요를 한 번만 누를 수 있도록 복합키 설정
    CONSTRAINT `fk_log_like_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_log_like_log` FOREIGN KEY (`log_id`) REFERENCES `trip_log` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 기록 이미지 (Log Image)
CREATE TABLE `log_image` (
    `id`            BIGINT NOT NULL AUTO_INCREMENT,
    `log_id`        BIGINT, -- 로그 저장 전 임시 업로드 상태일 수 있으므로 NULL 허용
    `user_id`       BIGINT NOT NULL,
    `image_url`     VARCHAR(255) NOT NULL,
    `order_index`   INT NOT NULL COMMENT '인스타 피드 뷰에서의 표시 순서',
    `image_ref_key` VARCHAR(50) NOT NULL COMMENT '본문 {{key}}와 매핑되는 고유 키 (프론트 생성)',
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_log_image_log` FOREIGN KEY (`log_id`) REFERENCES `trip_log` (`id`) ON DELETE SET NULL,
    CONSTRAINT `fk_log_image_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 기록 댓글 (Log Comment)
CREATE TABLE `log_comment` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `log_id`      BIGINT NOT NULL,
  `user_id`     BIGINT NOT NULL,
  `content`     TEXT NOT NULL,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_comment_log` FOREIGN KEY (`log_id`) REFERENCES `trip_log` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_comment_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 8. 시드 데이터 (초기 데이터)
-- =================================================================

-- 기본 역할
INSERT INTO `role` (id, code, name) VALUES
(1, 'USER',  '일반 사용자'),
(2, 'ADMIN', '관리자');

-- 기본 사용자 상태
INSERT INTO `user_status` (id, code, name, description) VALUES
(1, 'ACTIVE',  '활성', '일반 활성 사용자'),
(2, 'DELETED', '탈퇴', '탈퇴 또는 비활성 사용자');

-- 기본 Trip Status
INSERT INTO `trip_status` (id, code, name, description) VALUES
(1, 'DRAFT',     '작성 중',   '작성 중인 여행 계획'),
(2, 'PLANNED',   '계획 완료', '여행 계획 완료 상태'),
(3, 'COMPLETED', '여행 완료', '여행이 실제로 완료된 상태');
