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
