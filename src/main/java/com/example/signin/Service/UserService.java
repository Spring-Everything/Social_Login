package com.example.signin.Service;

import com.example.signin.DTO.JWTDTO;
import com.example.signin.DTO.UserDTO;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Map;

public interface UserService {
    boolean isUidDuplicate(String uid);
    boolean isNicknameDuplicate(String nickname);
    UserDTO createUser(UserDTO userDTO);
    JWTDTO login(String uid, String password);
    List<UserDTO> getAllUser(String uid, UserDetails userDetails);
    UserDTO getUserByUid(String uid, UserDetails userDetails);
    UserDTO getUserByNickname(String uid, String nickname, UserDetails userDetails);
    List<UserDTO> searchUserByNickname(String uid, String nickname, UserDetails userDetails);
    UserDTO updateUser(String uid, UserDTO userDTO, UserDetails userDetails);
    UserDTO deleteUser(String uid, UserDetails userDetails);
    Long refreshToken(UserDetails userDetails);
    Long getTokenRemainingTime(UserDetails userDetails);
    JWTDTO getUserWithTokenInfo(String uid, String token, UserDetails userDetails);
    UserDTO updateNickname(String uid, String nickname, UserDetails userDetails);
    String getKakaoAccessToken(String code);
    JWTDTO loginWithKakaoOAuth2(String code);
    Map<String, Object> getNaverUserInfo(String accessToken);
    JWTDTO loginWithNaverOAuth2(String code);
    JWTDTO loginWithGoogleOAuth2(String code);
    Map<String, Object> getGoogleUserInfo(String accessToken);
    JWTDTO loginWithFacebookOAuth2(String code);
    Map<String, Object> getFacebookUserInfo(String accessToken);
    JWTDTO loginWithGithubOAuth2(String code);
    Map<String, Object> getGithubUserInfo(String accessToken);
}

