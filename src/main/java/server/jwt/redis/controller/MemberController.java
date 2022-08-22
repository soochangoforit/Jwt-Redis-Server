package server.jwt.redis.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.dto.request.AccessTokenForLogout;
import server.jwt.redis.dto.request.RefreshTokenRequestDto;
import server.jwt.redis.dto.request.SignUpRequestDto;
import server.jwt.redis.dto.response.BasicResponse;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.jwt.JwtProvider;
import server.jwt.redis.jwt.PrincipalDetails;
import server.jwt.redis.service.MemberService;
import server.jwt.redis.service.RequestService;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
@Slf4j
public class MemberController {

    private final MemberService memberService;
    private final RequestService requestService;
    private final JwtProvider jwtProvider;

    @GetMapping("/home")
    public String login() {
        return "loginPage";
    }

    @PostMapping("/signup")
    @ResponseBody
    public ResponseEntity<BasicResponse> signUp(@RequestBody SignUpRequestDto signUpUser) {
        memberService.signUp(signUpUser.getUsername(), signUpUser.getPassword() , signUpUser.getEmail() , signUpUser.getNickname());
        BasicResponse response = new BasicResponse("회원가입 성공", HttpStatus.CREATED);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }


    @GetMapping(value = "/refresh")
    @ResponseBody
    public ResponseEntity<LoginResponseDto> reIssue(@CookieValue(name="refreshToken") String refreshToken , HttpServletRequest request) throws IOException {

        String clientIp = requestService.getClientIp(request);

        LoginResponseDto responseDto = memberService.reIssueAccessToken(refreshToken, clientIp);

        // todo : refresh token은 바로 cookie에 넣어주자


        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @GetMapping("/test")
    @ResponseBody
    public String test(@AuthenticationPrincipal String id) {
        return id;
    }

    @GetMapping("/logout")
    @ResponseBody
    public ResponseEntity<BasicResponse> logout(@CookieValue(name="refreshToken") String refreshToken, HttpServletRequest request) {

        String accessToken = request.getHeader(AUTHORIZATION).substring(7);

        memberService.logout(accessToken, refreshToken);

        BasicResponse response = new BasicResponse("로그아웃 성공", HttpStatus.OK);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }


}
