-- =================================================================
-- 데이터베이스 설정 (2차 설계 통합)
-- =================================================================
DROP DATABASE IF EXISTS jjtrip_dev;
CREATE DATABASE jjtrip_dev DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE jjtrip_dev;

-- =================================================================
-- 1. 유저 및 권한 (User & Auth)
-- =================================================================

-- 역할 (Role)
CREATE TABLE `role` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE COMMENT "'USER', 'ADMIN'",
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 상태 (User Status)
CREATE TABLE `user_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) NOT NULL UNIQUE COMMENT "'ACTIVE', 'DELETED'",
  `name`        VARCHAR(50) NOT NULL,
  `description` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 (User)
CREATE TABLE `user` (
  `id`                BIGINT NOT NULL AUTO_INCREMENT,
  `role_id`           BIGINT NOT NULL,
  `status_id`         BIGINT NOT NULL,
  `email`             VARCHAR(100) UNIQUE,
  `password_hash`     VARCHAR(255),
  `nickname`          VARCHAR(50),
  `profile_image_url` VARCHAR(255),
  `created_at`        DATETIME DEFAULT NOW(),
  `updated_at`        DATETIME,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_user_role` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `fk_user_status` FOREIGN KEY (`status_id`) REFERENCES `user_status` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자 프로필 (User Profile) - 기존 테이블 유지
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

-- 친구 관계 (Friendship) - 기존 테이블 유지
CREATE TABLE `friendship` (
  `user_id_a`  BIGINT NOT NULL,
  `user_id_b`  BIGINT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id_a`, `user_id_b`),
  CONSTRAINT `fk_friendship_user_a` FOREIGN KEY (`user_id_a`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_friendship_user_b` FOREIGN KEY (`user_id_b`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_friendship_order` CHECK (`user_id_a` < `user_id_b`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 2. 장소 (Spot) - 2차 설계 반영
-- =================================================================

CREATE TABLE `spot` (
  `id`             BIGINT NOT NULL AUTO_INCREMENT,
  `kakao_place_id` VARCHAR(50) UNIQUE NOT NULL COMMENT "카카오맵 고유 ID",
  `name`           VARCHAR(100) NOT NULL,
  `address`        VARCHAR(255),
  `category`       VARCHAR(50),
  `lat`            DECIMAL(10,8) NOT NULL,
  `lng`            DECIMAL(11,8) NOT NULL,
  `place_url`      VARCHAR(255),
  `thumbnail_url`  VARCHAR(255),
  `review_count`   INT DEFAULT 0,
  `average_rating` DECIMAL(3,2) DEFAULT 0,
  `created_at`     DATETIME DEFAULT NOW(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 3. 여행 계획 (Trip Plan) - 2차 설계 반영
-- =================================================================

-- 여행 상태 마스터
CREATE TABLE `trip_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) UNIQUE NOT NULL COMMENT "'DRAFT', 'PLANNED', 'COMPLETED'",
  `name`        VARCHAR(50) NOT NULL COMMENT "작성 중, 계획 완료, 여행 완료",
  `description` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 계획
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

-- 여행 계획 아이템
CREATE TABLE `trip_item` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `trip_id`     BIGINT NOT NULL,
  `spot_id`     BIGINT NOT NULL,
  `day_number`  INT NOT NULL COMMENT "1일차, 2일차...",
  `order_index` INT NOT NULL COMMENT "방문 순서",
  `memo`        TEXT,
  `created_at`  DATETIME DEFAULT NOW(), -- Added created_at column
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_trip_item_trip` FOREIGN KEY (`trip_id`) REFERENCES `trip` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_trip_item_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- =================================================================
-- 4. 여행 로그 (Trip Log) - [신규]
-- =================================================================

CREATE TABLE `trip_log` (
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`          BIGINT NOT NULL,
  `original_trip_id` BIGINT COMMENT "어떤 여행 계획을 바탕으로 작성되었는지 (선택)",
  `title`            VARCHAR(100) NOT NULL,
  `content`          TEXT NOT NULL,
  `visibility`       VARCHAR(20) NOT NULL DEFAULT 'PRIVATE' COMMENT "'PUBLIC' 또는 'PRIVATE'",
  `created_at`       DATETIME DEFAULT NOW(),
  `updated_at`       DATETIME,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_trip_log_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_trip_log_original_trip` FOREIGN KEY (`original_trip_id`) REFERENCES `trip` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 5. 리뷰 (Review) - [신규]
-- =================================================================

CREATE TABLE `review` (
  `id`        BIGINT NOT NULL AUTO_INCREMENT,
  `spot_id`   BIGINT NOT NULL,
  `user_id`   BIGINT NOT NULL,
  `content`   TEXT NOT NULL,
  `rating`    INT NOT NULL COMMENT "1 ~ 5 점",
  `image_url` VARCHAR(255),
  `created_at` DATETIME DEFAULT NOW(),
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_review_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_review_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 6. 스크랩 (Scrap) - [신규]
-- =================================================================

CREATE TABLE `scrap` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`         BIGINT NOT NULL COMMENT "스크랩한 유저",
  `scrappable_id`   BIGINT NOT NULL COMMENT "스크랩된 대상의 ID (spot.id, trip.id, trip_log.id 등)",
  `scrappable_type` VARCHAR(50) NOT NULL COMMENT "스크랩된 대상의 타입 ('SPOT', 'TRIP', 'TRIP_LOG')",
  `created_at`      DATETIME DEFAULT NOW(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_scrap` (`user_id`, `scrappable_id`, `scrappable_type`),
  CONSTRAINT `fk_scrap_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 7. 기존 테이블 유지 (채팅, 저널 등)
-- =================================================================

-- 지역 유형 (Region Type) - 기존 테이블 유지
CREATE TABLE `region_type` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE,
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 지역 (Region) - 기존 테이블 유지
CREATE TABLE `region` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `parent_id`    BIGINT,
  `type_id`      BIGINT NOT NULL,
  `name`         VARCHAR(100) NOT NULL,
  `code`         VARCHAR(50),
  `slug`         VARCHAR(100),
  `timezone`     VARCHAR(50),
  `created_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_region_parent` FOREIGN KEY (`parent_id`) REFERENCES `region` (`id`),
  CONSTRAINT `fk_region_type` FOREIGN KEY (`type_id`) REFERENCES `region_type` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 태그 카테고리 (Tag Category) - 기존 테이블 유지
CREATE TABLE `tag_category` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE,
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 태그 (Tag) - 기존 테이블 유지
CREATE TABLE `tag` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `name`        VARCHAR(50) NOT NULL UNIQUE,
  `category_id` BIGINT,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_tag_category` FOREIGN KEY (`category_id`) REFERENCES `tag_category` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 채팅방 유형 (Chat Room Type) - 기존 테이블 유지
CREATE TABLE `chat_room_type` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE,
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 채팅방 (Chat Room) - 기존 테이블 유지
CREATE TABLE `chat_room` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `name`       VARCHAR(100),
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 저널 (Travel Journal) - 기존 테이블 유지. FK는 나중에 수동으로 연결해야 할 수 있음.
CREATE TABLE `travel_journal` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`      BIGINT NOT NULL,
  `title`        VARCHAR(120) NOT NULL,
  `diary`        TEXT,
  `is_private`   BOOLEAN NOT NULL DEFAULT FALSE,
  `is_deleted`   BOOLEAN NOT NULL DEFAULT FALSE,
  `created_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_travel_journal_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- =================================================================
-- 8. 시드 데이터 (Seed Data)
-- =================================================================

-- 기본 역할
INSERT INTO `role` (id, code, name) VALUES (1, 'USER', '일반 사용자'), (2, 'ADMIN', '관리자');

-- 기본 사용자 상태
INSERT INTO `user_status` (id, code, name, description) VALUES (1, 'ACTIVE', '활성', '일반 활성 사용자'), (2, 'DELETED', '탈퇴', '탈퇴 또는 비활성 사용자');

-- 여행 상태 마스터
INSERT INTO `trip_status` (id, code, name, description) VALUES (1, 'DRAFT', '작성중', '작성중인 여행 계획'), (2, 'PLANNED', '계획완료', '여행 계획이 완료된 상태'), (3, 'COMPLETED', '여행완료', '실제로 여행이 완료된 상태');

-- 더미 사용자 (사용자 제공 계정)
INSERT INTO `user` (id, role_id, status_id, email, password_hash, nickname) VALUES
(1, 1, 1, 'hi@hi.hi', '$2a$10$uyMhCnceQ3ORnCNk.wvfOeZt3EqtJNKzlD0OYZ.veOJYa2SgPFszu', '테스트 계정1'),
(2, 1, 1, 'hi1@hi.hi', '$2a$10$uB2MdvuEvR460eGyC/H8w.j3ghCsBzLFRN7FOXpbG0vjCTx6o9n2K', '테스트 계정2'),
(3, 1, 1, 'hi2@hi.hi', '$2a$10$1cA1Jc5KIeCCfBGAPKBbH.pt5dDiSKTgRX/j8aixQa1Pk8xB2Dreq', '테스트 계정3');

-- 더미 사용자 프로필 (사용자 제공 계정)
INSERT INTO `user_profile` (user_id, bio, intro, friends_count) VALUES
(1, '안녕하세요! 테스트 계정1입니다.', '테스트 계정 1의 자기소개', 2),
(2, '안녕하세요! 테스트 계정2입니다.', '테스트 계정 2의 자기소개', 2),
(3, '안녕하세요! 테스트 계정3입니다.', '테스트 계정 3의 자기소개', 2);

-- 더미 친구 관계
INSERT INTO `friendship` (user_id_a, user_id_b) VALUES (1, 2);
INSERT INTO `friendship` (user_id_a, user_id_b) VALUES (1, 3);
INSERT INTO `friendship` (user_id_a, user_id_b) VALUES (2, 3);
INSERT INTO `spot` (kakao_place_id, name, address, category, lat, lng, place_url) VALUES
('27392064', '아쿠아플라넷 제주', '제주 서귀포시 성산읍 섭지코지로 95', '테마파크', 33.43041, 126.9242, 'http://place.map.kakao.com/27392064'),
('8035229', '성산일출봉', '제주 서귀포시 성산읍 성산리 1', '명소', 33.45806, 126.9425, 'http://place.map.kakao.com/8035229'),
('7948366', '카멜리아힐', '제주 서귀포시 안덕면 병악로 166', '공원', 33.2989, 126.3939, 'http://place.map.kakao.com/7948366');

-- 더미 여행 계획
INSERT INTO `trip` (user_id, trip_status_id, title, start_date, end_date, visibility) VALUES
(1, 2, '제주도 2박 3일 여행', '2024-03-10', '2024-03-12', 'PUBLIC');

-- 더미 여행 아이템
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index, memo) VALUES
(1, 1, 1, 1, '오전 10시 도착 예정'),
(1, 2, 2, 1, '일출 보러 가기'),
(1, 3, 2, 2, '점심 먹고 산책');
