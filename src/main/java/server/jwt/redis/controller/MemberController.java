package server.jwt.redis.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.WebUtils;
import server.jwt.redis.domain.Member;
import server.jwt.redis.domain.enums.Role;
import server.jwt.redis.dto.request.AccessTokenForLogout;
import server.jwt.redis.dto.request.RefreshTokenRequestDto;
import server.jwt.redis.dto.request.SignUpRequestDto;
import server.jwt.redis.dto.response.BasicResponse;
import server.jwt.redis.dto.response.DefaultDataResponse;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.exception.BadRequestException;
import server.jwt.redis.jwt.JwtProvider;
import server.jwt.redis.jwt.PrincipalDetails;
import server.jwt.redis.repository.MemberRepository;
import server.jwt.redis.service.MemberService;
import server.jwt.redis.service.RequestService;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
@Slf4j
public class MemberController {

    private final MemberService memberService;
    private final RequestService requestService;
    private final MemberRepository memberRepository;

    @GetMapping("/home")
    public String login() {
        return "loginPage";
    }

    /**
     * 회원가입 성공시 200
     * 중복된 회원 존재 혹은 비밀번호 형식이 맞지 않는 경우 400 Bad Request 응답
     * @param signUpUser 회원가입 요청 DTO
     */
    @PostMapping("/signup")
    @ResponseBody
    public ResponseEntity<BasicResponse> signUp(@RequestBody SignUpRequestDto signUpUser) {
        memberService.signUp(signUpUser.getUsername(), signUpUser.getPassword() , signUpUser.getEmail() , signUpUser.getNickname());
        BasicResponse response = new BasicResponse(HttpStatus.CREATED.value(), "회원가입 성공");
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }


    @GetMapping(value = "/refresh")
    @ResponseBody
    public ResponseEntity<DefaultDataResponse> reIssue(@CookieValue(name = "refreshToken") String refreshToken ,HttpServletRequest request,
                                                    HttpServletResponse response) throws IOException {

        String clientIp = requestService.getClientIp(request);

        Map<String, String> tokenMap = memberService.reIssueAccessToken(refreshToken, clientIp);

        LoginResponseDto responseDto = new LoginResponseDto(tokenMap.get("accessToken"));

        // refresh token은 cookie에 담아주기
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenMap.get("refreshToken"))
                .maxAge(1 * 24 * 60 * 60) // 1 day
                .httpOnly(true)
                .path("/")
                .build();

        response.setHeader("Set-Cookie",cookie.toString());

        return new ResponseEntity<>(DefaultDataResponse.of(HttpStatus.OK.value(), "재발급 성공" ,responseDto), HttpStatus.OK);
    }

    @GetMapping("/test")
    @ResponseBody
    public String test(@AuthenticationPrincipal String id) {

        Member member = memberRepository.findById(Long.parseLong(id)).get();
        return member.getUsername() + "님 환영합니다.";
    }

    @GetMapping("/logout")
    @ResponseBody
    public ResponseEntity<BasicResponse> logout(@CookieValue(name="refreshToken") String refreshToken, HttpServletRequest request,
                                                HttpServletResponse response) throws IOException {

        String accessToken = request.getHeader(AUTHORIZATION).substring(7);

        memberService.logout(accessToken, refreshToken);

        // logout 시 refresh token 삭제
        ResponseCookie cookie = ResponseCookie.from("refreshToken", null)
                .maxAge(0) // 1 day
                .build();

        response.setHeader("Set-Cookie",cookie.toString());

        BasicResponse responseOfBasic = new BasicResponse(HttpStatus.OK.value(),"로그아웃 성공" );
        return new ResponseEntity<>(responseOfBasic, HttpStatus.OK);
    }


}
