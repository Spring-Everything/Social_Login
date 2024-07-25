package com.example.signin.Service;

import com.example.signin.Entity.UserEntity;
import com.example.signin.Repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public CustomOAuth2UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        // Kakao 사용자 정보 추출
        Long id = oAuth2User.getAttribute(userNameAttributeName);
        Map<String, Object> properties = oAuth2User.getAttribute("properties");
        Map<String, Object> kakaoAccount = oAuth2User.getAttribute("kakao_account");

        String name = properties != null ? (String) properties.get("nickname") : null;
        String email = kakaoAccount != null ? (String) kakaoAccount.get("email") : null;

        // 사용자가 이미 존재하는지 확인
        Optional<UserEntity> userEntityOptional = userRepository.findByUid(String.valueOf(id));
        UserEntity userEntity;
        if (userEntityOptional.isPresent()) {
            userEntity = userEntityOptional.get();
            // 이름 업데이트
            userEntity.setName(name);
        } else {
            // 존재하지 않으면 새로 생성
            userEntity = UserEntity.builder()
                    .uid(String.valueOf(id))
                    .name(name)
                    .password(passwordEncoder.encode("OAuth2_User_Password")) // 비밀번호 설정
                    .provider(registrationId)
                    .build();
            userRepository.save(userEntity);
        }

        // OAuth2User 반환
        return new CustomOAuth2User(userEntity, oAuth2User.getAttributes());
    }
}
