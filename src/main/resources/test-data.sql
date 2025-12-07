DROP DATABASE IF EXISTS jjtrip_dev;
CREATE DATABASE jjtrip_dev;
USE jjtrip_dev;

-- 🔐 권한 (Role)
CREATE TABLE `role` (
  `id`   BIGINT NOT NULL AUTO_INCREMENT,
  `code` VARCHAR(20) NOT NULL UNIQUE,  -- 'USER', 'ADMIN' 등
  `name` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 👤 유저 상태 (User Status)
CREATE TABLE `user_status` (
  `id`          BIGINT NOT NULL AUTO_INCREMENT,
  `code`        VARCHAR(20) NOT NULL UNIQUE,  -- 'ACTIVE', 'BANNED' 등
  `name`        VARCHAR(50) NOT NULL,
  `description` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 👤 유저 (User)
CREATE TABLE `user` (
  `id`                BIGINT NOT NULL AUTO_INCREMENT,
  `role_id`           BIGINT NOT NULL,
  `status_id`         BIGINT NOT NULL,
  `email`             VARCHAR(100),
  `password_hash`     VARCHAR(255) NOT NULL,
  `nickname`          VARCHAR(50) NOT NULL,
  `profile_image_url` VARCHAR(255),
  `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),

  KEY `idx_user_email` (`email`),
  CONSTRAINT `fk_user_role`
    FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `fk_user_status`
    FOREIGN KEY (`status_id`) REFERENCES `user_status` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 기본 Role
INSERT INTO role (id, code, name) VALUES
(1, 'USER', '일반 사용자'),
(2, 'ADMIN', '관리자');

-- 기본 User Status
INSERT INTO user_status (id, code, name, description) VALUES
(1, 'ACTIVE', '활성', '정상 사용 가능한 계정'),
(2, 'DELETED', '탈퇴', '탈퇴한 계정 (로그인 불가)');

-- 테스트 User
INSERT INTO user (
  id, role_id, status_id, email, password_hash, nickname, profile_image_url, created_at, updated_at
) VALUES
(1, 1, 1, 'test@example.com', 'hashedpassword123', '테스트유저', NULL, now(), now());
