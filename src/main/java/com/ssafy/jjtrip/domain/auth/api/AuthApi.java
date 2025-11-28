package com.ssafy.jjtrip.domain.auth.api;

import com.ssafy.jjtrip.domain.auth.dto.LoginRequestDto;
import com.ssafy.jjtrip.domain.auth.dto.LoginResponseDto;
import com.ssafy.jjtrip.domain.auth.dto.SignupRequestDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

@Tag(name = "Auth", description = "인증 관련 API")
public interface AuthApi {

    @Operation(
            summary = "로그인",
            description = "이메일과 비밀번호로 로그인하고 AccessToken/RefreshToken을 발급합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "로그인 성공",
                    content = @Content(
                            schema = @Schema(implementation = LoginResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "이메일 또는 비밀번호가 올바르지 않음"
            )
    })
    ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto request);

    @Operation(
            summary = "회원가입",
            description = "이메일, 비밀번호, 닉네임으로 회원가입을 진행합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "회원가입 성공"
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "이미 존재하는 이메일"
            )
    })
    ResponseEntity<?> signup(@Valid @RequestBody SignupRequestDto request);
}
