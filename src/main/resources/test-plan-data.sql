-- 1. 데이터베이스 생성 및 선택
DROP DATABASE IF EXISTS jjtrip_dev;
CREATE DATABASE jjtrip_dev DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE jjtrip_dev;

-- ==========================================
-- 🔐 1. 유저 및 권한 (Auth Domain)
-- ==========================================

-- 권한 (Role)
CREATE TABLE `role` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `code`       VARCHAR(20) NOT NULL UNIQUE, -- 'USER', 'ADMIN'
  `name`       VARCHAR(50) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 유저 상태 (Status)
CREATE TABLE `user_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) NOT NULL UNIQUE, -- 'ACTIVE', 'DELETED'
  `name`        VARCHAR(50) NOT NULL,
  `description` VARCHAR(100),
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 유저 (User)
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
  CONSTRAINT `fk_user_role` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `fk_user_status` FOREIGN KEY (`status_id`) REFERENCES `user_status` (`id`)
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
  `visibility`     VARCHAR(20) NOT NULL DEFAULT 'PRIVATE', -- 'PUBLIC' 또는 'PRIVATE'
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_trip_user`        FOREIGN KEY (`user_id`)        REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_trip_trip_status` FOREIGN KEY (`trip_status_id`) REFERENCES `trip_status` (`id`)
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
-- 📖 4. 여행 로그 (Trip Log Domain)
-- ==========================================

CREATE TABLE `trip_log` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`          BIGINT NOT NULL,
  `original_trip_id` BIGINT NULL,  -- 어떤 여행 계획을 기준으로 작성되었는지 (선택)
  `title`            VARCHAR(100) NOT NULL,
  `content`          TEXT NOT NULL,
  `visibility`       VARCHAR(20) NOT NULL DEFAULT 'PRIVATE', -- 'PUBLIC' 또는 'PRIVATE'
  `created_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  CONSTRAINT `fk_trip_log_user`          FOREIGN KEY (`user_id`)          REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_trip_log_original_trip` FOREIGN KEY (`original_trip_id`) REFERENCES `trip` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==========================================
-- 📝 5. 리뷰 (Review Domain)
-- ==========================================

CREATE TABLE `review` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `spot_id`     BIGINT NOT NULL,
  `user_id`     BIGINT NOT NULL,
  `content`     TEXT NOT NULL,
  `rating`      INT NOT NULL,        -- 1 ~ 5 점
  `image_url`   VARCHAR(255),
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_review_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_review_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==========================================
-- 📌 6. 스크랩 (Scrap Domain)
-- ==========================================

CREATE TABLE `scrap` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`         BIGINT NOT NULL,  -- 스크랩한 유저
  `scrappable_id`   BIGINT NOT NULL,  -- 대상 ID (spot.id, trip.id, trip_log.id 등)
  `scrappable_type` VARCHAR(50) NOT NULL, -- 'SPOT', 'TRIP', 'TRIP_LOG'
  `created_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),

  CONSTRAINT `fk_scrap_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,

  UNIQUE KEY `uk_scrap_user_target` (`user_id`, `scrappable_id`, `scrappable_type`),
  INDEX `idx_scrap_target` (`scrappable_type`, `scrappable_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ==========================================
-- ⚙️ 7. 초기 기초 데이터 (Seed Data)
-- ==========================================

-- 기본 Role
INSERT INTO `role` (id, code, name, created_at) VALUES
(1, 'USER',  '일반 사용자', NOW()),
(2, 'ADMIN', '관리자',     NOW());

-- 기본 User Status
INSERT INTO `user_status` (id, code, name, description, created_at) VALUES
(1, 'ACTIVE',  '활성', '일반 활성 사용자', NOW()),
(2, 'DELETED', '탈퇴', '탈퇴 또는 비활성 사용자', NOW());

-- 기본 Trip Status
INSERT INTO `trip_status` (id, code, name, description) VALUES
(1, 'DRAFT',     '작성 중',   '작성 중인 여행 계획'),
(2, 'PLANNED',   '계획 완료', '여행 계획 완료 상태'),
(3, 'COMPLETED', '여행 완료', '여행이 실제로 완료된 상태');
