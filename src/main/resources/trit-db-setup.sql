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

-- 더미 사용자 (사용자 제공 계정)
INSERT INTO `user` (id, role_id, status_id, email, password_hash, nickname, profile_image_url) VALUES
(1, 1, 1, 'hi@hi.hi', '$2a$10$uyMhCnceQ3ORnCNk.wvfOeZt3EqtJNKzlD0OYZ.veOJYa2SgPFszu', '테스트 계정1', 'https://dh.aks.ac.kr/Edu/wiki/images/b/b7/%ED%95%91%EA%B5%AC.jpg'),
(2, 1, 1, 'hi1@hi.hi', '$2a$10$uB2MdvuEvR460eGyC/H8w.j3ghCsBzLFRN7FOXpbG0vjCTx6o9n2K', '테스트 계정2', 'https://i.namu.wiki/i/w4Vkm_EuVM_FV8-VDjLVJPWazkrT1YnkSFLVASCh4YM8QUebla94cM8j42z8hQPzJQCyVcDlm71EeKgPzLyMfg.webp'),
(3, 1, 1, 'hi2@hi.hi', '$2a$10$1cA1Jc5KIeCCfBGAPKBbH.pt5dDiSKTgRX/j8aixQa1Pk8xB2Dreq', '테스트 계정3', 'https://i.namu.wiki/i/2Vk0cSYgfHODE4-SrICeOk7qaQCz09wqivf27QgdZawQ5lg3YKo-XjL9BvyvkBeQ-JGE_dV83cYnsd5urD65aw.webp');

-- 더미 사용자 프로필 (사용자 제공 계정)
INSERT INTO `user_profile` (user_id, bio, intro, friends_count) VALUES
(1, '안녕하세요! 테스트 계정1입니다.', '테스트 계정 1의 자기소개', 2),
(2, '안녕하세요! 테스트 계정2입니다.', '테스트 계정 2의 자기소개', 2),
(3, '안녕하세요! 테스트 계정3입니다.', '테스트 계정 3의 자기소개', 2);

-- 더미 친구 관계
INSERT INTO `friendship` (user_id_a, user_id_b) VALUES (1, 2);
INSERT INTO `friendship` (user_id_a, user_id_b) VALUES (1, 3);
INSERT INTO `friendship` (user_id_a, user_id_b) VALUES (2, 3);

-- 더미 장소
INSERT INTO `spot` (kakao_place_id, name, address, category, lat, lng, place_url) VALUES
('27392064', '아쿠아플라넷 제주', '제주 서귀포시 성산읍 섭지코지로 95', '테마파크', 33.43041, 126.9242, 'http://place.map.kakao.com/27392064'),
('8035229', '성산일출봉', '제주 서귀포시 성산읍 성산리 1', '명소', 33.45806, 126.9425, 'http://place.map.kakao.com/8035229'),
('7948366', '카멜리아힐', '제주 서귀포시 안덕면 병악로 166', '공원', 33.2989, 126.3939, 'http://place.map.kakao.com/7948366');

-- 더미 여행 계획
INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility) VALUES
(1, 1, 2, '제주도 2박 3일 여행', '2024-03-10', '2024-03-12', 'PUBLIC');

-- 더미 여행 아이템
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index, memo) VALUES
(1, 1, 1, 1, '오전 10시 도착 예정'),
(1, 2, 2, 1, '일출 보러 가기'),
(1, 3, 2, 2, '점심 먹고 산책');

-- 더미 여행 로그 (이미지 플레이스홀더 적용: 고유 키 방식)
-- {{img_a1b2}} 처럼 프론트가 생성한 고유 키를 사용
INSERT INTO `trip_log` (id, trip_id, title, content, location_summary) VALUES
(1, 1, '제주도 2박 3일 여행기',
'이번 제주도 여행의 시작은 아쿠아플라넷이었습니다.\n\n{{img_key_1}}\n\n수족관 규모가 정말 커서 놀랐어요. 상어도 보고 가오리도 봤네요.\n그 다음날 아침에는 일출을 보러 갔습니다.\n\n{{img_key_2}}\n\n날씨가 좋아서 해 뜨는 게 아주 잘 보였습니다. 정말 잊지 못할 추억이에요.',
'제주 서귀포시');

-- 더미 여행 기록 이미지 (image_ref_key 포함)
-- order_index: 피드 뷰 정렬용
-- image_ref_key: 블로그 뷰 본문 매핑용
INSERT INTO `log_image` (log_id, user_id, image_url, order_index, image_ref_key) VALUES
(1, 1, 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQvytJIR9t4OyaATlDacK5xwsF7rd3yiMgWGQ&s', 0, 'img_key_1'),
(1, 1, 'https://img1.daumcdn.net/thumb/R1280x0.fjpg/?fname=http://t1.daumcdn.net/brunch/service/user/1lcG/image/ATFUCOF_RrI4V7UWgZCF_g139sY.jpg', 1, 'img_key_2');

-- 더미 로그 댓글
INSERT INTO `log_comment` (log_id, user_id, content) VALUES
(1, 2, '와 여행 너무 좋아보여요! 사진 멋지네요.'),
(1, 3, '다음엔 저도 같이 가요 ㅎㅎ');

-- 더미 로그 좋아요
INSERT INTO `log_like` (user_id, log_id) VALUES
(2, 1),
(3, 1);
