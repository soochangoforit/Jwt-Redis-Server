package server.jwt.redis.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import server.jwt.redis.dto.request.LoginRequestDto;
import server.jwt.redis.dto.request.SignUpRequestDto;
import server.jwt.redis.dto.response.BasicResponse;
import server.jwt.redis.dto.response.LoginResponseDto;
import server.jwt.redis.service.MemberService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/sign-up")
    public ResponseEntity<BasicResponse> signUp(@RequestBody SignUpRequestDto signUpUser) {
        memberService.signUp(signUpUser.getEmail(), signUpUser.getEmail(), signUpUser.getPassword());
        BasicResponse response = new BasicResponse("회원가입 성공", HttpStatus.CREATED);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginDto) {
        LoginResponseDto responseDto = memberService.login(loginDto.getEmail(), loginDto.getPassword());
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }


    @GetMapping("/re-issue")
    public ResponseEntity<LoginResponseDto> reIssue(@RequestParam("email") String email, @RequestParam("refreshToken") String refreshToken) {
        LoginResponseDto responseDto = memberService.reIssueAccessToken(email, refreshToken);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

}