-- 3. 장소 (Spot) 데이터 생성 (Kakao Place ID 등은 더미 데이터)
-- 연희동 Spot (ID: 1~4)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(1, 'kakao_1001', '연희동사진관', '서울 서대문구 연희동 1', 37.5671, 126.9301, '문화시설'),
(2, 'kakao_1002', '바늘이야기', '서울 서대문구 연희동 2', 37.5672, 126.9302, '공방'),
(3, 'kakao_1003', '매뉴팩트커피', '서울 서대문구 연희동 3', 37.5673, 126.9303, '카페'),
(4, 'kakao_1004', '궁동근린공원', '서울 서대문구 연희동 4', 37.5674, 126.9304, '공원');

-- 망원동 Spot (ID: 5~9)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(5, 'kakao_2001', '망원시장', '서울 마포구 망원동 1', 37.5551, 126.9051, '시장'),
(6, 'kakao_2002', '당도', '서울 마포구 망원동 2', 37.5552, 126.9052, '디저트'),
(7, 'kakao_2003', '제로퍼제로', '서울 마포구 망원동 3', 37.5553, 126.9053, '소품샵'),
(8, 'kakao_2004', '망원한강공원', '서울 마포구 망원동 4', 37.5554, 126.9054, '공원'),
(9, 'kakao_2005', '스타벅스 망원한강공원점', '서울 마포구 망원동 5', 37.5555, 126.9055, '카페');

-- 성북동 Spot (ID: 10~13)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(10, 'kakao_3001', '나폴레옹과자점', '서울 성북구 성북동 1', 37.5881, 127.0081, '베이커리'),
(11, 'kakao_3002', '길상사', '서울 성북구 성북동 2', 37.5882, 127.0082, '문화재'),
(12, 'kakao_3003', '성북동면옥집', '서울 성북구 성북동 3', 37.5883, 127.0083, '음식점'),
(13, 'kakao_3004', '수연산방', '서울 성북구 성북동 4', 37.5884, 127.0084, '카페');

-- Trip 4: 서촌 (조용한 갤러리와 서점)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(14, 'kakao_4001', '보안여관', '서울 종로구 효자로 33', 37.5771, 126.9721, '문화공간'),
(15, 'kakao_4002', '대오서점', '서울 종로구 자하문로7길 55', 37.5772, 126.9722, '카페'),
(16, 'kakao_4003', '수성동계곡', '서울 종로구 옥인동 185-3', 37.5773, 126.9723, '자연'),
(17, 'kakao_4004', 'mk2', '서울 종로구 자하문로10길 17', 37.5774, 126.9724, '카페');

-- Trip 5: 서울숲 (평일 낮의 여유)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(18, 'kakao_5001', '할머니의레시피', '서울 성동구 서울숲2길 44-12', 37.5441, 127.0371, '한식'),
(19, 'kakao_5002', '센터커피', '서울 성동구 서울숲2길 28-11', 37.5442, 127.0372, '카페'),
(20, 'kakao_5003', '서울숲 거울연못', '서울 성동구 뚝섬로 273', 37.5443, 127.0373, '공원');

-- Trip 6: 낙산공원 (생각 정리하기 좋은 야경)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(21, 'kakao_6001', '이화동 벽화마을', '서울 종로구 이화동', 37.5751, 127.0061, '명소'),
(22, 'kakao_6002', '테르트르', '서울 종로구 낙산5길 46', 37.5752, 127.0062, '카페'),
(23, 'kakao_6003', '낙산공원 성곽길', '서울 종로구 낙산길 41', 37.5753, 127.0063, '공원');

-- Trip 7: 을지로 (비 오는 날 감성)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(24, 'kakao_7001', '호랑이', '서울 중구 을지로 157', 37.5661, 126.9951, '카페'),
(25, 'kakao_7002', '세운상가', '서울 중구 청계천로 159', 37.5662, 126.9952, '명소'),
(26, 'kakao_7003', '평래옥', '서울 중구 마른내로 21-1', 37.5663, 126.9953, '음식점');

-- Trip 8: 한남동 (혼자 즐기는 문화생활)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(27, 'kakao_8001', '리움미술관', '서울 용산구 이태원로55길 60-16', 37.5381, 127.0011, '미술관'),
(28, 'kakao_8002', '현대카드 뮤직라이브러리', '서울 용산구 이태원로 246', 37.5382, 127.0012, '문화공간'),
(29, 'kakao_8003', '콘하스 한남', '서울 용산구 이태원로55나길 22', 37.5383, 127.0013, '카페');

-- Trip 9: 덕수궁 (가을 정취 느끼기)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(30, 'kakao_9001', '덕수궁', '서울 중구 세종대로 99', 37.5651, 126.9751, '문화재'),
(31, 'kakao_9002', '리에제와플', '서울 중구 덕수궁길 5', 37.5652, 126.9752, '디저트'),
(32, 'kakao_9003', '서울시립미술관', '서울 중구 덕수궁길 61', 37.5653, 126.9753, '미술관');

-- Trip 10: 부암동 (서울 속 숲속 같은 고요함)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(33, 'kakao_10001', '스코프', '서울 종로구 창의문로 149', 37.5931, 126.9631, '베이커리'),
(34, 'kakao_10002', '윤동주문학관', '서울 종로구 창의문로 119', 37.5932, 126.9632, '문화공간'),
(35, 'kakao_10003', '산모퉁이', '서울 종로구 백석동길 153', 37.5933, 126.9633, '카페');

-- -----------------------------------------------------------------
-- 3. 장소 (Spot) 등록 (ID 100번대 사용)
-- -----------------------------------------------------------------
-- (기존과 동일한 장소 데이터 사용)

-- Trip 11: 북한산
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(101, 'kakao_u2_01', '북한산 백운대 탐방지원센터', '서울 강북구 우이동', 37.6581, 127.0081, '관광명소'),
(102, 'kakao_u2_02', '북한산 백운대 정상', '경기 고양시 덕양구', 37.6582, 127.0082, '산'),
(103, 'kakao_u2_03', '산두부집', '서울 강북구 삼양로 173길', 37.6583, 127.0083, '음식점');

-- Trip 12: 롯데월드
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(104, 'kakao_u2_04', '감성교복', '서울 송파구 석촌호수로 234', 37.5091, 127.0981, '대여점'),
(105, 'kakao_u2_05', '롯데월드 어드벤처', '서울 송파구 올림픽로 240', 37.5111, 127.0982, '테마파크'),
(106, 'kakao_u2_06', '아틀란티스', '서울 송파구 올림픽로 240', 37.5112, 127.0983, '놀이기구');

-- Trip 13: 뚝섬 한강공원
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(107, 'kakao_u2_07', '뚝섬 윈드서핑장', '서울 광진구 강변북로 2326', 37.5291, 127.0701, '수상레저'),
(108, 'kakao_u2_08', '한강라면 자판기(뚝섬)', '서울 광진구 자양동', 37.5292, 127.0702, '편의점'),
(109, 'kakao_u2_09', '서울생각마루', '서울 광진구 강변북로 2202', 37.5293, 127.0703, '문화공간');

-- Trip 14: 성수동
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(110, 'kakao_u2_10', '성수 디올', '서울 성동구 연무장5길 7', 37.5445, 127.0541, '명소'),
(111, 'kakao_u2_11', '포인트오브뷰', '서울 성동구 연무장길 18', 37.5446, 127.0542, '소품샵'),
(112, 'kakao_u2_12', '텅 성수', '서울 성동구 성수이로 82', 37.5447, 127.0543, '카페');

-- Trip 15: 홍대
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(113, 'kakao_u2_13', '더클라임 연남', '서울 마포구 양화로 186', 37.5571, 126.9241, '스포츠'),
(114, 'kakao_u2_14', '비트포비아 던전', '서울 마포구 와우산로 29길', 37.5572, 126.9242, '놀이문화'),
(115, 'kakao_u2_15', '브로스버거', '서울 마포구 홍익로', 37.5573, 126.9243, '음식점');


-- -----------------------------------------------------------------
-- 2. 여행 (Trip) 등록 (ID 4~10)
-- -----------------------------------------------------------------

INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility, location_summary) VALUES
(4, 1, 3, '서촌에서 혼자 놀기 📚', '2024-10-05', '2024-10-05', 'PUBLIC', '서울 종로구 서촌'),
(5, 1, 3, '평일 연차 쓰고 서울숲 힐링 🌳', '2024-10-20', '2024-10-20', 'PUBLIC', '서울 성동구 서울숲'),
(6, 1, 3, '답답해서 다녀온 낙산공원 야경 ✨', '2024-11-02', '2024-11-02', 'PUBLIC', '서울 종로구 낙산공원'),
(7, 1, 3, '비 오는 날의 힙지로 감성 ☔️', '2024-11-15', '2024-11-15', 'PUBLIC', '서울 중구 을지로'),
(8, 1, 3, '한남동에서 귀 호강 눈 호강 🎧', '2024-12-01', '2024-12-01', 'PUBLIC', '서울 용산구 한남동'),
(9, 1, 3, '덕수궁 돌담길 걷기 🍂', '2024-12-10', '2024-12-10', 'PUBLIC', '서울 중구 정동'),
(10, 1, 3, '복잡한 게 싫을 땐 부암동으로 ⛰', '2024-12-24', '2024-12-24', 'PUBLIC', '서울 종로구 부암동');

-- -----------------------------------------------------------------
-- 4. 여행 (Trip) 등록 - 제목 단순화
-- -----------------------------------------------------------------

INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility, location_summary) VALUES
(11, 2, 3, '북한산', '2024-09-14', '2024-09-14', 'PUBLIC', '서울 강북구 북한산'),
(12, 2, 3, '롯데월드', '2024-10-03', '2024-10-03', 'PUBLIC', '서울 송파구 잠실'),
(13, 2, 3, '뚝섬 한강공원', '2024-08-20', '2024-08-20', 'PUBLIC', '서울 광진구 뚝섬'),
(14, 2, 3, '성수동', '2024-11-11', '2024-11-11', 'PUBLIC', '서울 성동구 성수동'),
(15, 2, 3, '홍대', '2024-12-05', '2024-12-05', 'PUBLIC', '서울 마포구 홍대');

-- 4. 여행 (Trip) 생성
-- Trip 1: 연희동
INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility, location_summary)
VALUES (1, 1, 3, '날씨 미쳤던 연희동 골목 산책 🌿', '2024-05-10', '2024-05-10', 'PUBLIC', '서울 서대문구 연희동');

-- Trip 2: 망원동
INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility, location_summary)
VALUES (2, 1, 3, '퇴근하고 망원한강공원 번개️', '2024-06-21', '2024-06-21', 'PUBLIC', '서울 마포구 망원동');

-- Trip 3: 성북동
INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility, location_summary)
VALUES (3, 1, 3, '주말엔 성북동 빵지순례 🥐', '2024-09-07', '2024-09-07', 'PUBLIC', '서울 성북구 성북동');

-- Trip 4 (서촌)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(4, 17, 1, 1), (4, 14, 1, 2), (4, 15, 1, 3), (4, 16, 1, 4);

-- Trip 5 (서울숲)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(5, 18, 1, 1), (5, 19, 1, 2), (5, 20, 1, 3);

-- Trip 6 (낙산공원)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(6, 21, 1, 1), (6, 22, 1, 2), (6, 23, 1, 3);

-- Trip 7 (을지로)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(7, 26, 1, 1), (7, 24, 1, 2), (7, 25, 1, 3);

-- Trip 8 (한남동)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(8, 27, 1, 1), (8, 28, 1, 2), (8, 29, 1, 3);

-- Trip 9 (덕수궁)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(9, 31, 1, 1), (9, 30, 1, 2), (9, 32, 1, 3);

-- Trip 10 (부암동)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(10, 33, 1, 1), (10, 34, 1, 2), (10, 35, 1, 3);

-- 5. 여행 상세 아이템 (Trip Item) - 경로 매핑
-- Trip 1 (연희동) : Spot 1 -> 2 -> 3 -> 4
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(1, 1, 1, 1),
(1, 2, 1, 2),
(1, 3, 1, 3),
(1, 4, 1, 4);

-- Trip 2 (망원동) : Spot 5 -> 6 -> 7 -> 8 -> 9
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(2, 5, 1, 1),
(2, 6, 1, 2),
(2, 7, 1, 3),
(2, 8, 1, 4),
(2, 9, 1, 5);

-- Trip 3 (성북동) : Spot 10 -> 11 -> 12 -> 13
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(3, 10, 1, 1),
(3, 11, 1, 2),
(3, 12, 1, 3),
(3, 13, 1, 4);

-- Trip 11 (북한산)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(11, 101, 1, 1), (11, 102, 1, 2), (11, 103, 1, 3);

-- Trip 12 (롯데월드)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(12, 104, 1, 1), (12, 105, 1, 2), (12, 106, 1, 3);

-- Trip 13 (뚝섬 한강공원)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(13, 107, 1, 1), (13, 108, 1, 2), (13, 109, 1, 3);

-- Trip 14 (성수동)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(14, 110, 1, 1), (14, 111, 1, 2), (14, 112, 1, 3);

-- Trip 15 (홍대)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(15, 113, 1, 1), (15, 115, 1, 2), (15, 114, 1, 3);

-- Log 4
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(4, 4, '서촌에서 혼자 놀기 📚',
'사람 많은 건 딱 질색이라 평일에 조용히 다녀온 서촌.
오래된 서점에서 나는 종이 냄새도 좋고, 수성동 계곡 물소리 들으면서 앉아있으니 잡생각이 싹 사라짐.
이런 게 찐행복이지. 혼자만의 시간이 필요한 사람들에게 무조건 추천!

#서촌 #서촌카페 #대오서점 #혼자여행 #사색', 'PUBLIC');

-- Log 5
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(5, 5, '평일 연차 쓰고 서울숲 힐링 🌳',
'아껴뒀던 연차 쓰고 서울숲 런. 주말엔 사람 터지는데 평일 낮이라 그런지 한적하고 너무 평화롭다.
할머니의 레시피에서 든든하게 밥 먹고 센터커피에서 라떼 한 잔 들고 거울연못 앞에 앉아있기.
초록초록한 거 보니까 눈이 맑아지는 기분! 역시 자연이 최고야.

#서울숲 #평일연차 #피크닉 #숲캉스 #성수동맛집', 'PUBLIC');

-- Log 6
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(6, 6, '답답해서 다녀온 낙산공원 야경 ✨',
'마음이 좀 답답해서 퇴근하고 무작정 낙산공원행.
성곽길 따라 쭉 걷다 보면 서울 시내가 한눈에 들어오는데, 반짝이는 불빛들 보고 있으니 위로받는 느낌.
테르트르 카페 뷰는 진짜 반칙 수준.. 멍때리기 딱 좋다.

#낙산공원 #서울야경 #성곽길 #밤산책 #드라이브', 'PUBLIC');

-- Log 7
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(7, 7, '비 오는 날의 힙지로 감성 ☔️',
'비 오니까 괜히 더 센치해져서 을지로 골목 탐방.
간판도 없는 좁은 골목 찾아다니는 재미가 쏠쏠함. 호랑이 라떼는 역시 명불허전 고소하고 달달해.
세운상가 옥상에서 비 맞는 서울 풍경 보는 것도 꽤 운치 있다.

#을지로 #힙지로 #호랑이커피 #비오는날 #레트로', 'PUBLIC');

-- Log 8
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(8, 8, '한남동에서 귀 호강 눈 호강 🎧',
'오랜만에 문화생활 즐기러 한남동 나들이.
리움미술관 건축물은 언제 봐도 압도적이고, 뮤직라이브러리에서 LP 듣는데 시간이 멈춘 줄 알았다.
좋아하는 음악 들으면서 걷는 이태원 거리는 또 다른 느낌.

#한남동 #리움미술관 #바이닐앤플라스틱 #문화생활 #전시회', 'PUBLIC');

-- Log 9
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(9, 9, '덕수궁 돌담길 걷기 🍂',
'겨울 오기 전에 막차 탄 가을 덕수궁.
돌담길 걷다가 리에제 와플 사 먹는 건 국룰인 거 아시죠? 따뜻한 와플 호호 불면서 먹는 맛이란..
시립미술관 전시까지 보고 나오니 하루가 꽉 찬 느낌.

#덕수궁 #돌담길 #정동길 #와플맛집 #서울산책', 'PUBLIC');

-- Log 10
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(10, 10, '복잡한 게 싫을 땐 부암동으로 ⛰',
'서울에 이런 곳이 있나 싶을 정도로 조용한 부암동.
윤동주 문학관 들렀다가 산모퉁이 카페 올라가는 길은 좀 힘들지만, 테라스 뷰 보는 순간 힘듦이 싹 잊혀짐.
조용히 책 읽거나 생각 정리하고 싶을 때 제일 먼저 생각나는 곳.

#부암동 #산모퉁이 #북악스카이웨이 #조용한카페 #힐링여행', 'PUBLIC');


-- 6. 여행 기록 (Trip Log) - 인스타 감성 본문
-- Log 1: 연희동
INSERT INTO `trip_log` (id, trip_id, title, content, visibility)
VALUES (1, 1, '날씨 미쳤던 연희동 골목 산책 🌿',
'오늘 날씨 진짜 무슨 일이야.. 햇살 너무 좋아서 무작정 걸었는데 힐링 그 자체ㅠㅠ
골목마다 예쁜 가게 너무 많아서 카메라 셔터 계속 눌렀음.
조용하게 혼자 걷고 싶을 때 강추하는 코스! 다들 꼭 가보세요.

#연희동 #연희동카페 #산책 #일상 #감성샷', 'PUBLIC');

-- Log 2: 망원동
INSERT INTO `trip_log` (id, trip_id, title, content, visibility)
VALUES (2, 2, '퇴근하고 망원한강공원 번개 ⚡️',
'스트레스 받을 땐 역시 한강이지.
망원시장에서 맛있는 거 잔뜩 사서 돗자리 펴놓고 먹으니까 천국이 따로 없음.
오늘 노을 색감 실화냐.. 핑크빛 하늘 보면서 힐링 완료! 내일도 화이팅하자.

#망원동 #한강피크닉 #노을맛집 #망원시장 #먹스타그램', 'PUBLIC');

-- Log 3: 성북동
INSERT INTO `trip_log` (id, trip_id, title, content, visibility)
VALUES (3, 3, '주말엔 성북동 빵지순례 🥐',
'늦잠 자고 일어나서 빵 냄새 맡으러 성북동 출동!
고즈넉한 한옥이랑 세련된 빵집들이 섞여 있어서 분위기 묘하게 좋음.
오르막길이라 강제 운동 되긴 하는데 먹으려면 이 정도는 감수해야지 ㅋㅋ 데이트 코스로도 추천!

#성북동 #빵지순례 #빵순이 #주말데이트 #한옥뷰', 'PUBLIC');


-- -----------------------------------------------------------------
-- 6. 여행 기록 (Trip Log) 등록 - 담백한 어조
-- -----------------------------------------------------------------

-- Log 11
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(11, 11, '북한산 백운대 정복',
'이른 아침부터 서둘러 북한산으로 향했습니다. 올라가는 길은 꽤 힘들었지만, 정상인 백운대에 도착하니 탁 트인 서울 전경 덕분에 피로가 씻기는 기분이었습니다.
태극기 앞에서 기념사진도 남기고, 하산 후에는 근처 식당에서 두부김치와 막걸리를 먹었습니다. 등산 후에 먹는 음식이라 더욱 맛있었습니다.', 'PUBLIC');

-- Log 12
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(12, 12, '롯데월드에서 교복 입고 놀기',
'오랜만에 교복을 대여해 입고 롯데월드에 다녀왔습니다.
운 좋게 대기 시간이 길지 않아 아틀란티스를 비롯해 여러 놀이기구를 즐길 수 있었습니다.
매직캐슬 앞에서 사진도 찍고 즐거운 시간을 보냈습니다. 가끔은 이렇게 동심으로 돌아가 보는 것도 좋은 것 같습니다.', 'PUBLIC');

-- Log 13
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(13, 13, '한강에서 선셋 카약 타기',
'매번 산책만 하던 한강에서 이번에는 카약 체험을 해보았습니다.
노를 젓는 것이 생각보다 힘이 들었지만, 물 위에서 바라보는 노을 풍경이 정말 아름다웠습니다.
운동 후 편의점에서 끓여 먹는 라면까지 완벽한 하루였습니다.', 'PUBLIC');

-- Log 14
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(14, 14, '성수동 팝업스토어 투어',
'요즘 볼거리가 많다는 성수동을 방문했습니다.
다양한 팝업스토어들이 열려 있어 구경하는 재미가 있었습니다.
포인트오브뷰에서 문구류도 구경하고, 카페에서 잠시 쉬어가며 여유롭게 돌아다녔습니다. 많이 걸어서 운동도 된 것 같습니다.', 'PUBLIC');

-- Log 15
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(15, 15, '홍대 클라이밍과 방탈출 체험',
'퇴근 후 홍대에서 실내 클라이밍에 도전했습니다.
어려운 코스를 완등했을 때의 성취감이 컸습니다.
운동을 마친 뒤에는 근처 햄버거 가게에서 저녁을 먹고, 방탈출 카페에서 게임을 즐기며 하루를 마무리했습니다.', 'PUBLIC');

-- 7. 로그 이미지 (Log Image) - 더미 이미지
INSERT INTO `log_image` (log_id, user_id, image_url, order_index, image_ref_key) VALUES
-- 연희동 이미지
(1, 1, 'https://example.com/img/yeonhui_1.jpg', 1, 'img_1'),
(1, 1, 'https://example.com/img/yeonhui_2.jpg', 2, 'img_2'),
-- 망원동 이미지
(2, 1, 'https://example.com/img/mangwon_1.jpg', 1, 'img_1'),
(2, 1, 'https://example.com/img/mangwon_2.jpg', 2, 'img_2'),
(2, 1, 'https://example.com/img/mangwon_3.jpg', 3, 'img_3'),
-- 성북동 이미지
(3, 1, 'https://example.com/img/seongbuk_1.jpg', 1, 'img_1'),
(3, 1, 'https://example.com/img/seongbuk_2.jpg', 2, 'img_2');

-- Trip 16: 광장시장 (육회, 빈대떡)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(201, 'kakao_u3_01', '부촌육회', '서울 종로구 종로 200-12', 37.5701, 126.9991, '음식점'),
(202, 'kakao_u3_02', '순희네빈대떡', '서울 종로구 종로32길 5', 37.5702, 126.9992, '음식점'),
(203, 'kakao_u3_03', '광장시장', '서울 종로구 창경궁로 88', 37.5703, 126.9993, '시장');

-- Trip 17: 을지로 평양냉면 (노포)
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(204, 'kakao_u3_04', '우래옥', '서울 중구 창경궁로 62-29', 37.5681, 126.9981, '음식점'),
(205, 'kakao_u3_05', '을지면옥', '서울 중구 충무로14길 2-1', 37.5682, 126.9982, '음식점'),
(206, 'kakao_u3_06', '만선호프', '서울 중구 을지로3가', 37.5683, 126.9983, '술집');

-- Trip 18: 남대문 갈치조림
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(207, 'kakao_u3_07', '남대문 갈치조림 골목', '서울 중구 남대문시장길', 37.5591, 126.9771, '음식점'),
(208, 'kakao_u3_08', '가메골 손왕만두', '서울 중구 남대문시장4길 42', 37.5592, 126.9772, '음식점'),
(209, 'kakao_u3_09', '남대문시장', '서울 중구 남대문시장4길 21', 37.5593, 126.9773, '시장');

-- Trip 19: 신당동 떡볶이
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(210, 'kakao_u3_10', '마복림할머니집', '서울 중구 다산로35길 5', 37.5651, 127.0161, '음식점'),
(211, 'kakao_u3_11', '신당동 떡볶이 타운', '서울 중구 신당동', 37.5652, 127.0162, '명소'),
(212, 'kakao_u3_12', '더피터커피', '서울 중구 다산로35길 20', 37.5653, 127.0163, '카페');

-- Trip 20: 약수역 금돼지
INSERT INTO `spot` (id, kakao_place_id, name, address, lat, lng, category) VALUES
(213, 'kakao_u3_13', '금돼지식당', '서울 중구 다산로 149', 37.5561, 127.0101, '음식점'),
(214, 'kakao_u3_14', '약수순대국', '서울 중구 다산로8길 7', 37.5562, 127.0102, '음식점'),
(215, 'kakao_u3_15', '리사르커피', '서울 중구 다산로8길 16-7', 37.5563, 127.0103, '카페');


-- -----------------------------------------------------------------
-- 4. 여행 (Trip) 등록 - 단순한 지명 위주 제목
-- -----------------------------------------------------------------

INSERT INTO `trip` (id, user_id, trip_status_id, title, start_date, end_date, visibility, location_summary) VALUES
(16, 3, 3, '광장시장', '2024-09-20', '2024-09-20', 'PUBLIC', '서울 종로구 예지동'),
(17, 3, 3, '을지로 평양냉면', '2024-10-15', '2024-10-15', 'PUBLIC', '서울 중구 주교동'),
(18, 3, 3, '남대문시장', '2024-11-05', '2024-11-05', 'PUBLIC', '서울 중구 남창동'),
(19, 3, 3, '신당동', '2024-11-22', '2024-11-22', 'PUBLIC', '서울 중구 신당동'),
(20, 3, 3, '약수동', '2024-12-12', '2024-12-12', 'PUBLIC', '서울 중구 신당동');

-- -----------------------------------------------------------------
-- 5. 여행 상세 (Trip Item) 등록
-- -----------------------------------------------------------------

-- Trip 16 (광장시장)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(16, 203, 1, 1), (16, 202, 1, 2), (16, 201, 1, 3);

-- Trip 17 (을지로)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(17, 204, 1, 1), (17, 205, 1, 2), (17, 206, 1, 3);

-- Trip 18 (남대문)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(18, 209, 1, 1), (18, 207, 1, 2), (18, 208, 1, 3);

-- Trip 19 (신당동)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(19, 211, 1, 1), (19, 210, 1, 2), (19, 212, 1, 3);

-- Trip 20 (약수동)
INSERT INTO `trip_item` (trip_id, spot_id, day_number, order_index) VALUES
(20, 213, 1, 1), (20, 214, 1, 2), (20, 215, 1, 3);


-- -----------------------------------------------------------------
-- 6. 여행 기록 (Trip Log) 등록 - "했다. 좋았다!" 스타일
-- -----------------------------------------------------------------

-- Log 16
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(16, 16, '광장시장에서 빈대떡과 육회 먹기',
'친구들과 광장시장에 갔다.
유명하다는 순희네 빈대떡과 부촌육회를 방문했다.
기름에 튀기듯 구운 빈대떡 맛이 일품이었다. 신선한 육회도 고소하고 맛있었다.
사람이 너무 많아서 정신이 없었지만 활기찬 시장 분위기가 좋았다!', 'PUBLIC');

-- Log 17
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(17, 17, '을지로에서 평양냉면 투어',
'날씨가 쌀쌀해졌지만 평양냉면이 생각나서 을지로에 갔다.
오래된 노포 식당인 우래옥에 들러 냉면을 주문했다.
진한 육수 맛이 아주 좋았다. 냉면을 먹고 나서 만선호프에 들러 맥주도 한잔했다.
옛날 감성을 느낄 수 있어서 좋았다!', 'PUBLIC');

-- Log 18
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(18, 18, '남대문 갈치조림 골목 탐방',
'점심을 먹으러 남대문 시장 갈치조림 골목을 찾았다.
오래된 식당에서 매콤한 갈치조림을 먹었다. 양념 맛이 밥도둑이었다.
나오는 길에 왕만두도 포장했다. 저렴한 가격에 배부르게 먹을 수 있어서 좋았다!', 'PUBLIC');

-- Log 19
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(19, 19, '신당동 즉석 떡볶이 먹은 날',
'갑자기 떡볶이가 먹고 싶어서 신당동 떡볶이 타운에 갔다.
원조라는 마복림 할머니 집에 가서 2인 세트를 시켰다.
보글보글 끓여 먹는 즉석 떡볶이 맛이 그리웠다.
다 먹고 볶음밥까지 볶아 먹었다. 역시 변하지 않는 맛이라 좋았다!', 'PUBLIC');

-- Log 20
INSERT INTO `trip_log` (id, trip_id, title, content, visibility) VALUES
(20, 20, '약수역 금돼지식당 웨이팅 성공',
'미슐랭 맛집이라는 금돼지식당에 도전했다.
웨이팅이 길었지만 기다린 보람이 있었다.
직원이 고기를 알맞게 구워줘서 편하게 먹었다. 육즙이 가득해서 정말 맛있었다.
후식으로 근처 리사르 커피에서 에스프레소도 마셨다. 완벽한 코스라 좋았다!', 'PUBLIC');
