-- =================================================================
-- 데이터베이스 설정
-- =================================================================
DROP DATABASE IF EXISTS jjtrip_dev;
CREATE DATABASE jjtrip_dev DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE jjtrip_dev;

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

-- =================================================================
-- 2. 지역
-- =================================================================

-- 지역 유형 (Region Type)
CREATE TABLE `region_type` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'CITY', 'DISTRICT'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 지역 (Region)
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

-- 지역 경계 (Region Boundary)
CREATE TABLE `region_boundary` (
  `region_id`        BIGINT NOT NULL,
  `boundary_geojson` TEXT NOT NULL,
  `created_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`region_id`),
  CONSTRAINT `fk_region_boundary_region` FOREIGN KEY (`region_id`) REFERENCES `region` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 3. 장소 관련
-- =================================================================

-- 장소 상태 (Spot Status)
CREATE TABLE `spot_status` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'ACTIVE', 'CLOSED'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 카테고리 (Spot Category)
CREATE TABLE `spot_category` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL UNIQUE,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 (Spot)
CREATE TABLE `spot` (
  `id`                BIGINT NOT NULL AUTO_INCREMENT,
  `region_id`         BIGINT NOT NULL,
  `category_id`       BIGINT NOT NULL,
  `status_id`         BIGINT NOT NULL,
  `name`              VARCHAR(255) NOT NULL,
  `lat`               DOUBLE NOT NULL,
  `lon`               DOUBLE NOT NULL,
  `summary`           TEXT,
  `address`           TEXT,
  `phone`             VARCHAR(50),
  `primary_photo_url` TEXT,
  `source_provider`   VARCHAR(50),
  `source_place_id`   VARCHAR(100),
  `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_source_place` (`source_provider`, `source_place_id`),
  KEY `idx_lat_lon` (`lat`, `lon`),
  CONSTRAINT `fk_spot_region` FOREIGN KEY (`region_id`) REFERENCES `region` (`id`),
  CONSTRAINT `fk_spot_category` FOREIGN KEY (`category_id`) REFERENCES `spot_category` (`id`),
  CONSTRAINT `fk_spot_status` FOREIGN KEY (`status_id`) REFERENCES `spot_status` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 카테고리 맵 (Spot Category Map)
CREATE TABLE `spot_category_map` (
  `spot_id`     BIGINT NOT NULL,
  `category_id` BIGINT NOT NULL,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`spot_id`, `category_id`),
  CONSTRAINT `fk_spot_cat_map_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_spot_cat_map_category` FOREIGN KEY (`category_id`) REFERENCES `spot_category` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 사진 (Spot Photo)
CREATE TABLE `spot_photo` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `spot_id`    BIGINT NOT NULL,
  `url`        TEXT NOT NULL,
  `is_primary` BOOLEAN NOT NULL DEFAULT FALSE,
  `width`      INT,
  `height`     INT,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_spot_photo_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 영업시간 (Spot Hour)
CREATE TABLE `spot_hour` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `spot_id`     BIGINT NOT NULL,
  `dow`         SMALLINT NOT NULL, -- 요일 (0=일, 1=월, ..., 6=토)
  `segment_no`  SMALLINT NOT NULL DEFAULT 1,
  `is_24h`      BOOLEAN NOT NULL DEFAULT FALSE,
  `open_time`   TIME,
  `close_time`  TIME,
  `break_start` TIME,
  `break_end`   TIME,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_spot_hour_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 영업시간 예외 (Spot Hour Exception)
CREATE TABLE `spot_hour_exception` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `spot_id`    BIGINT NOT NULL,
  `date`       DATE NOT NULL,
  `is_closed`  BOOLEAN NOT NULL DEFAULT FALSE,
  `open_time`  TIME,
  `close_time` TIME,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_spot_hour_exception_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 4. 태그
-- =================================================================

-- 태그 카테고리 (Tag Category)
CREATE TABLE `tag_category` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'THEME', 'MOOD'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 태그 (Tag)
CREATE TABLE `tag` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `name`        VARCHAR(50) NOT NULL UNIQUE,
  `category_id` BIGINT,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_tag_category` FOREIGN KEY (`category_id`) REFERENCES `tag_category` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 장소 태그 (Spot Tag)
CREATE TABLE `spot_tag` (
  `spot_id` BIGINT NOT NULL,
  `tag_id`  BIGINT NOT NULL,
  PRIMARY KEY (`spot_id`, `tag_id`),
  CONSTRAINT `fk_spot_tag_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_spot_tag_tag` FOREIGN KEY (`tag_id`) REFERENCES `tag` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 5. 여행 계획
-- =================================================================

-- 여행 상태 (Trip Status)
CREATE TABLE `trip_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) NOT NULL UNIQUE, -- 'DRAFT', 'PLANNED', 'COMPLETED'
  `name`        VARCHAR(50) NOT NULL,
  `description` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 계획 상태 (Plan Status)
CREATE TABLE `plan_status` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'PLANNED', 'DONE'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 계획 (Travel Plan)
CREATE TABLE `travel_plan` (
  `id`            BIGINT NOT NULL AUTO_INCREMENT,
  `user_id`       BIGINT NOT NULL,
  `status_id`     BIGINT NOT NULL,
  `title`         VARCHAR(100) NOT NULL,
  `summary`       VARCHAR(255),
  `planned_date`  DATE,
  `visited_date`  DATE,
  `region_code`   VARCHAR(50),
  `area_name`     VARCHAR(100),
  `thumbnail_url` VARCHAR(255),
  `is_public`     BOOLEAN NOT NULL DEFAULT TRUE,
  `is_deleted`    BOOLEAN NOT NULL DEFAULT FALSE,
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_travel_plan_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_plan_status` FOREIGN KEY (`status_id`) REFERENCES `plan_status` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 계획 아이템 (Travel Plan Item)
CREATE TABLE `travel_plan_item` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `plan_id`    BIGINT NOT NULL,
  `spot_id`    BIGINT NOT NULL,
  `order_no`   INT NOT NULL,
  `memo`       TEXT,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_plan_order` (`plan_id`, `order_no`),
  CONSTRAINT `fk_travel_plan_item_plan` FOREIGN KEY (`plan_id`) REFERENCES `travel_plan` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_plan_item_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 계획 태그 (Travel Plan Tag)
CREATE TABLE `travel_plan_tag` (
  `plan_id` BIGINT NOT NULL,
  `tag_id`  BIGINT NOT NULL,
  PRIMARY KEY (`plan_id`, `tag_id`),
  CONSTRAINT `fk_travel_plan_tag_plan` FOREIGN KEY (`plan_id`) REFERENCES `travel_plan` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_plan_tag_tag` FOREIGN KEY (`tag_id`) REFERENCES `tag` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 6. 채팅
-- =================================================================

-- 채팅방 유형 (Chat Room Type)
CREATE TABLE `chat_room_type` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'PLAN', 'DM'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 채팅방 (Chat Room)
CREATE TABLE `chat_room` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `plan_id`    BIGINT,
  `type_id`    BIGINT NOT NULL,
  `name`       VARCHAR(100),
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_chat_room_plan` FOREIGN KEY (`plan_id`) REFERENCES `travel_plan` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_chat_room_type` FOREIGN KEY (`type_id`) REFERENCES `chat_room_type` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 채팅방 멤버 (Chat Room Member)
CREATE TABLE `chat_room_member` (
  `room_id`   BIGINT NOT NULL,
  `user_id`   BIGINT NOT NULL,
  `joined_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (`room_id`, `user_id`),
  CONSTRAINT `fk_chat_room_member_room` FOREIGN KEY (`room_id`) REFERENCES `chat_room` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_chat_room_member_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 채팅 메시지 유형 (Chat Message Type)
CREATE TABLE `chat_message_type` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'TEXT', 'IMAGE'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 채팅 메시지 (Chat Message)
CREATE TABLE `chat_message` (
  `id`              BIGINT NOT NULL AUTO_INCREMENT,
  `room_id`         BIGINT NOT NULL,
  `sender_id`       BIGINT NOT NULL,
  `message_type_id` BIGINT NOT NULL,
  `content`         TEXT,
  `file_url`        VARCHAR(500),
  `created_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_deleted`      BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (`id`),
  KEY `idx_chat_message_room_created_at` (`room_id`, `created_at`),
  CONSTRAINT `fk_chat_message_room` FOREIGN KEY (`room_id`) REFERENCES `chat_room` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_chat_message_sender` FOREIGN KEY (`sender_id`) REFERENCES `user` (`id`),
  CONSTRAINT `fk_chat_message_type` FOREIGN KEY (`message_type_id`) REFERENCES `chat_message_type` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =================================================================
-- 7. 북마크, 일지, 프로필
-- =================================================================

-- 여행 계획 북마크 (Travel Plan Bookmark)
CREATE TABLE `travel_plan_bookmark` (
  `user_id`    BIGINT NOT NULL,
  `plan_id`    BIGINT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`, `plan_id`),
  CONSTRAINT `fk_travel_plan_bookmark_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_plan_bookmark_plan` FOREIGN KEY (`plan_id`) REFERENCES `travel_plan` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 일지 분위기 (Travel Journal Mood)
CREATE TABLE `travel_journal_mood` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE, -- 'HAPPY', 'TIRED'
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 일지 (Travel Journal)
CREATE TABLE `travel_journal` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `plan_id`      BIGINT NOT NULL,
  `user_id`      BIGINT NOT NULL,
  `visited_date` DATE NOT NULL,
  `title`        VARCHAR(120) NOT NULL,
  `diary`        TEXT,
  `mood_id`      BIGINT,
  `weather_note` VARCHAR(50),
  `companion`    VARCHAR(100),
  `rating`       TINYINT,
  `total_spent`  INT,
  `is_private`   BOOLEAN NOT NULL DEFAULT FALSE,
  `is_deleted`   BOOLEAN NOT NULL DEFAULT FALSE,
  `created_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_travel_journal_plan` FOREIGN KEY (`plan_id`) REFERENCES `travel_plan` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_journal_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_journal_mood` FOREIGN KEY (`mood_id`) REFERENCES `travel_journal_mood` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 여행 일지 사진 (Travel Journal Photo)
CREATE TABLE `travel_journal_photo` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `journal_id` BIGINT NOT NULL,
  `spot_id`    BIGINT,
  `url`        TEXT NOT NULL,
  `taken_at`   DATETIME,
  `caption`    TEXT,
  `order_no`   INT,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_travel_journal_photo_journal` FOREIGN KEY (`journal_id`) REFERENCES `travel_journal` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_travel_journal_photo_spot` FOREIGN KEY (`spot_id`) REFERENCES `spot` (`id`) ON DELETE SET NULL
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

-- 기본 여행 상태
INSERT INTO `trip_status` (id, code, name, description) VALUES
(1, 'DRAFT',     '작성중', '작성중인 여행 계획'),
(2, 'PLANNED',   '계획완료', '여행 계획이 완료된 상태'),
(3, 'COMPLETED', '여행완료', '실제로 여행이 완료된 상태');

-- 지역 유형
INSERT INTO `region_type` (id, code, name) VALUES
(1, 'CITY', '시'),
(2, 'PROVINCE', '도');

-- 지역 (최소 데이터)
INSERT INTO `region` (id, type_id, name, slug) VALUES
(1, 1, '서울', 'seoul'),
(2, 1, '부산', 'busan'),
(3, 1, '제주', 'jeju');

-- 장소 상태
INSERT INTO `spot_status` (id, code, name) VALUES
(1, 'ACTIVE', '운영중'),
(2, 'CLOSED', '폐업');

-- 장소 카테고리
INSERT INTO `spot_category` (id, name) VALUES
(1, '카페'),
(2, '관광지'),
(3, '레스토랑');

-- 태그 카테고리
INSERT INTO `tag_category` (id, code, name) VALUES
(1, 'THEME', '테마'),
(2, 'MOOD', '분위기');

-- 태그 (최소 데이터)
INSERT INTO `tag` (id, name, category_id) VALUES
(1, '힐링', 1),
(2, '액티비티', 1),
(3, '혼자여행', 1),
(4, '커플여행', 1),
(5, '가족여행', 1);

-- 계획 상태
INSERT INTO `plan_status` (id, code, name) VALUES
(1, 'PLANNED', '계획됨'),
(2, 'DONE', '완료');

-- 채팅방 유형
INSERT INTO `chat_room_type` (id, code, name) VALUES
(1, 'PLAN', '계획'),
(2, 'DM', '다이렉트 메시지');

-- 채팅 메시지 유형
INSERT INTO `chat_message_type` (id, code, name) VALUES
(1, 'TEXT', '텍스트'),
(2, 'IMAGE', '이미지');

-- 여행 일지 분위기
INSERT INTO `travel_journal_mood` (id, code, name) VALUES
(1, 'HAPPY', '행복함'),
(2, 'TIRED', '피곤함'),
(3, 'EXCITED', '신남'),
(4, 'RELAXED', '편안함');

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

-- 더미 친구 관계 (제거 - 사용자 수가 3명으로 변경됨)