package com.example.signin.Controller;

import com.example.signin.DTO.JWTDTO;
import com.example.signin.DTO.OAuth2CodeDTO;
import com.example.signin.DTO.UserDTO;
import com.example.signin.Service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // 회원 가입
    @Operation(summary = "회원 가입")
    @PostMapping
    public ResponseEntity<UserDTO> createUser(@RequestBody UserDTO userDTO) {
        return ResponseEntity.ok(userService.createUser(userDTO));
    }

    // 로그인
    @Operation(summary = "로그인")
    @PostMapping("/login")
    public ResponseEntity<JWTDTO> login(@RequestBody UserDTO userDTO) {
        return ResponseEntity.ok(userService.login(userDTO.getUid(), userDTO.getPassword()));
    }

    // 유저 전체 조회
    @Operation(summary = "유저 전체 조회")
    @GetMapping("/all/{uid}")
    public ResponseEntity<List<UserDTO>> getAllUser(@PathVariable String uid, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.getAllUser(uid, userDetails));
    }

    // uid로 유저 조회
    @Operation(summary = "uid로 유저 조회")
    @GetMapping("/{uid}")
    public ResponseEntity<UserDTO> getUserByUid(@PathVariable String uid, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.getUserByUid(uid, userDetails));
    }

    // 닉네임으로 유저 조회
    @Operation(summary = "닉네임으로 유저 조회")
    @GetMapping("/{uid}/{nickname}")
    public ResponseEntity<UserDTO> getUserByNickname(@PathVariable String uid, @PathVariable String nickname, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.getUserByNickname(uid, nickname, userDetails));
    }

    // 닉네임 검색으로 유저 조회
    @Operation(summary = "닉네임 검색으로 유저 조회")
    @GetMapping("/search/{uid}")
    public ResponseEntity<List<UserDTO>> searchUserByNickname(@PathVariable String uid, @RequestParam String nickname, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.searchUserByNickname(uid, nickname, userDetails));
    }

    // 아이디 중복 확인
    @Operation(summary = "아이디 중복 확인")
    @GetMapping("/check-uid")
    public ResponseEntity<Boolean> isUidDuplicate(@RequestBody String uid) {
        return ResponseEntity.ok(userService.isUidDuplicate(uid));
    }

    // 닉네임 중복 확인
    @Operation(summary = "닉네임 중복 확인")
    @GetMapping("/check-nickname")
    public ResponseEntity<Boolean> isNicknameDuplicate(@RequestBody String nickname) {
        return ResponseEntity.ok(userService.isNicknameDuplicate(nickname));
    }

    // 회원 정보 수정
    @Operation(summary = "회원 정보 수정")
    @PutMapping("/{uid}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable String uid, @RequestBody UserDTO userDTO, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.updateUser(uid, userDTO, userDetails));
    }

    // 회원 탈퇴
    @Operation(summary = "회원 탈퇴")
    @DeleteMapping("/{uid}")
    public ResponseEntity<UserDTO> deleteUser(@PathVariable String uid, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.deleteUser(uid, userDetails));
    }

    // 토큰 유효 시간 확인
    @Operation(summary = "토큰 유효 시간 확인")
    @GetMapping("/token-remaining-time")
    public ResponseEntity<Long> getTokenRemainingTime(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.getTokenRemainingTime(userDetails));
    }

    // 토큰 연장 (오류나는 중)
    @Operation(summary = "토큰 연장 (에러나는 중)")
    @PostMapping("/extend-token")
    public ResponseEntity<Long> refreshToken(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok( userService.refreshToken(userDetails));
    }

    // 유저 토큰 정보 조회
    @Operation(summary = "유저 토큰 정보 조회")
    @GetMapping("/token/{uid}")
    public ResponseEntity<JWTDTO> getUserWithTokenInfo(@PathVariable String uid, @RequestHeader("Authorization") String token, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.getUserWithTokenInfo(uid, token, userDetails));
    }

    // 닉네임 수정
    @Operation(summary = "닉네임 수정")
    @PutMapping("/nickname/{uid}")
    public ResponseEntity<UserDTO> updateNickname(@PathVariable String uid, @RequestBody String nickname, @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userService.updateNickname(uid, nickname, userDetails));
    }

    // 카카오 유저 닉네임 설정
    @Operation(summary = "카카오 유저 닉네임 설정")
    @PostMapping("/nickname/{uid}")
    public ResponseEntity<UserDTO> updateNickname(@PathVariable String uid, @RequestBody Map<String, String> request, @AuthenticationPrincipal UserDetails userDetails) {
        String nickname = request.get("nickname");
        return ResponseEntity.ok(userService.updateNickname(uid, nickname, userDetails));
    }

    // 카카오 로그인 성공 시 호출되는 엔드포인트 (GET)
    @Operation(summary = "카카오 로그인 성공 시 호출되는 엔드포인트 (GET)")
    @GetMapping("/oauth2/code/kakao")
    public ResponseEntity<JWTDTO> kakaoCallback(@RequestParam String code) {
        return ResponseEntity.ok(userService.loginWithKakaoOAuth2(code));
    }

    // 카카오 로그인 성공 시 호출되는 엔드포인트 (POST)
    @Operation(summary = "카카오 로그인 성공 시 호출되는 엔드포인트 (POST)")
    @PostMapping("/oauth2/code/kakao")
    public ResponseEntity<JWTDTO> kakaoLoginPost(@RequestBody OAuth2CodeDTO codeDTO) {
        return ResponseEntity.ok(userService.loginWithKakaoOAuth2(codeDTO.getCode()));
    }

    // 네이버 로그인 성공 시 호출되는 엔드포인트 (GET)
    @Operation(summary = "네이버 로그인 성공 시 호출되는 엔드포인트 (GET)")
    @GetMapping("/oauth2/code/naver")
    public ResponseEntity<JWTDTO> naverCallback(@RequestParam String code) {
        return ResponseEntity.ok(userService.loginWithNaverOAuth2(code));
    }

    // 네이버 로그인 성공 시 호출되는 엔드포인트 (POST)
    @Operation(summary = "네이버 로그인 성공 시 호출되는 엔드포인트 (POST)")
    @PostMapping("/oauth2/code/naver")
    public ResponseEntity<JWTDTO> naverLoginPost(@RequestBody OAuth2CodeDTO codeDTO) {
        return ResponseEntity.ok(userService.loginWithNaverOAuth2(codeDTO.getCode()));
    }

    // 구글 로그인 성공 시 호출되는 엔드포인트 (GET)
    @Operation(summary = "구글 로그인 성공 시 호출되는 엔드포인트 (GET)")
    @GetMapping("/oauth2/code/google")
    public ResponseEntity<JWTDTO> googleCallback(@RequestParam String code) {
        return ResponseEntity.ok(userService.loginWithGoogleOAuth2(code));
    }

    // 구글 로그인 성공 시 호출되는 엔드포인트 (POST)
    @Operation(summary = "구글 로그인 성공 시 호출되는 엔드포인트 (POST)")
    @PostMapping("/oauth2/code/google")
    public ResponseEntity<JWTDTO> googleLoginPost(@RequestBody OAuth2CodeDTO codeDTO) {
        return ResponseEntity.ok(userService.loginWithGoogleOAuth2(codeDTO.getCode()));
    }

    // 페이스북 로그인 성공 시 호출되는 엔드포인트 (GET)
    @Operation(summary = "페이스북 로그인 성공 시 호출되는 엔드포인트 (GET)")
    @GetMapping("/oauth2/code/facebook")
    public ResponseEntity<JWTDTO> facebookCallback(@RequestParam String code) {
        return ResponseEntity.ok(userService.loginWithFacebookOAuth2(code));
    }

    // 페이스북 로그인 성공 시 호출되는 엔드포인트 (POST)
    @Operation(summary = "페이스북 로그인 성공 시 호출되는 엔드포인트 (POST)")
    @PostMapping("/oauth2/code/facebook")
    public ResponseEntity<JWTDTO> facebookLoginPost(@RequestBody OAuth2CodeDTO codeDTO) {
        return ResponseEntity.ok(userService.loginWithFacebookOAuth2(codeDTO.getCode()));
    }

    // 깃허브 로그인 성공 시 호출되는 엔드포인트 (GET)
    @Operation(summary = "깃허브 로그인 성공 시 호출되는 엔드포인트 (GET)")
    @GetMapping("/oauth2/code/github")
    public ResponseEntity<JWTDTO> githubCallback(@RequestParam String code) {
        return ResponseEntity.ok(userService.loginWithGithubOAuth2(code));
    }

    // 깃허브 로그인 성공 시 호출되는 엔드포인트 (POST)
    @Operation(summary = "깃허브 로그인 성공 시 호출되는 엔드포인트 (POST)")
    @PostMapping("/oauth2/code/github")
    public ResponseEntity<JWTDTO> githubLoginPost(@RequestBody OAuth2CodeDTO codeDTO) {
        return ResponseEntity.ok(userService.loginWithGithubOAuth2(codeDTO.getCode()));
    }
}

