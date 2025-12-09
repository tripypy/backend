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

-- 여행 스타일 (Travel Style)
CREATE TABLE `travel_style` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'CAFE_LOVER'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 배지 (Badge)
CREATE TABLE `badge` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(50) NOT NULL UNIQUE,
  `name`        VARCHAR(100) NOT NULL,
  `description` VARCHAR(255),
  `icon_url`    VARCHAR(255),
  `category`    VARCHAR(30),
  `level`       INT,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 배지 (User Badge)
CREATE TABLE `user_badge` (
  `user_id`     BIGINT NOT NULL,
  `badge_id`    BIGINT NOT NULL,
  `obtained_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_pinned`   BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (`user_id`, `badge_id`),
  CONSTRAINT `fk_user_badge_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_user_badge_badge` FOREIGN KEY (`badge_id`) REFERENCES `badge` (`id`) ON DELETE CASCADE
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

-- 여행 스타일 (최소 데이터)
INSERT INTO `travel_style` (id, code, name) VALUES
(1, 'CAFE_HOPPER', '카페 탐방가'),
(2, 'ADVENTURER', '모험가'),
(3, 'FOODIE', '미식가');

-- 배지 (최소 데이터)
INSERT INTO `badge` (id, code, name, description, icon_url, category, level) VALUES
(1, 'FIRST_TRIP', '첫 여행', '첫 여행 계획 완료', NULL, 'TRIP', 1),
(2, 'PHOTO_MASTER', '사진 장인', '사진 100장 업로드', NULL, 'PHOTO', 2);

-- 더미 사용자 (사용자 제공 계정)
INSERT INTO `user` (id, role_id, status_id, email, password_hash, nickname, profile_image_url) VALUES
(1, 1, 1, 'hi@hi.hi', '$2a$10$uyMhCnceQ3ORnCNk.wvfOeZt3EqtJNKzlD0OYZ.veOJYa2SgPFszu', '테스트 계정1', NULL),
(2, 1, 1, 'hi1@hi.hi', '$2a$10$uB2MdvuEvR460eGyC/H8w.j3ghCsBzLFRN7FOXpbG0vjCTx6o9n2K', '테스트 계정2', NULL),
(3, 1, 1, 'hi2@hi.hi', '$2a$10$1cA1Jc5KIeCCfBGAPKBbH.pt5dDiSKTgRX/j8aixQa1Pk8xB2Dreq', '테스트 계정3', NULL);

-- 더미 사용자 프로필 (사용자 제공 계정)
INSERT INTO `user_profile` (user_id, bio, intro, home_region_id, travel_style_summary, travel_style_id, profile_banner_url, is_profile_public) VALUES
(1, '안녕하세요! 테스트 계정1입니다.', NULL, NULL, NULL, NULL, NULL, TRUE),
(2, '안녕하세요! 테스트 계정2입니다.', NULL, NULL, NULL, NULL, NULL, TRUE),
(3, '안녕하세요! 테스트 계정3입니다.', NULL, NULL, NULL, NULL, NULL, TRUE);
