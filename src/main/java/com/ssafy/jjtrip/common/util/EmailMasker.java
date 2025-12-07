package com.ssafy.jjtrip.common.util;

import org.springframework.stereotype.Component;

@Component // Make it a Spring component if it might need dependencies later, though static methods don't strictly require it.
public class EmailMasker {

    /**
     * 이메일 주소의 첫 글자를 제외하고 '@' 전까지 '*'로 마스킹합니다.
     * 예: example@domain.com -> e*****@domain.com
     *
     * @param email 마스킹할 이메일 주소
     * @return 마스킹된 이메일 주소
     */
    public static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email; // 유효하지 않은 이메일 형식은 마스킹하지 않고 그대로 반환
        }

        int atIndex = email.indexOf('@');
        String localPart = email.substring(0, atIndex); // @ 앞부분
        String domainPart = email.substring(atIndex);   // @ 뒷부분 포함

        if (localPart.length() <= 1) {
            // 첫 글자만 있거나 없는 경우 (예: a@domain.com) -> 마스킹할 부분이 없으므로 그대로 반환
            return email;
        }

        // 첫 글자를 제외한 나머지를 '*'로 대체
        String maskedLocalPart = localPart.charAt(0) + "*".repeat(localPart.length() - 1);

        return maskedLocalPart + domainPart;
    }
}
