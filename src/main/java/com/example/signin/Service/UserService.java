package com.example.signin.Service;

import com.example.signin.DTO.JWTDTO;
import com.example.signin.DTO.UserDTO;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

public interface UserService {
    UserDTO createUser(UserDTO userDTO);
    UserDTO getUserByUid(String uid);
    boolean isUidDuplicate(String uid);
    boolean isNicknameDuplicate(String nickname);
    JWTDTO login(String uid, String password);
    UserDTO updateUser(String uid, UserDTO userDTO, UserDetails userDetails);
    void deleteUser(String uid, UserDetails userDetails);
    Long refreshToken(UserDetails userDetails);
    Long getTokenRemainingTime(UserDetails userDetails);
    JWTDTO getUserWithTokenInfo(String uid, String token);
    UserDTO updateNickname(String uid, String nickname);
    UserDTO getKakaoUserInfo(String uid);
    String getAccessToken(String code);
    JWTDTO loginWithOAuth2(String code);
    Map<String, Object> getNaverUserInfo(String accessToken);
    JWTDTO loginWithNaverOAuth2(String code);
    JWTDTO loginWithGoogleOAuth2(String code);
    Map<String, Object> getGoogleUserInfo(String accessToken);
    JWTDTO loginWithFacebookOAuth2(String code);
    Map<String, Object> getFacebookUserInfo(String accessToken);
    JWTDTO loginWithGithubOAuth2(String code);
    Map<String, Object> getGithubUserInfo(String accessToken);
}

