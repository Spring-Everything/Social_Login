package com.example.signin.Service;

import com.example.signin.DTO.JWTDTO;
import com.example.signin.DTO.UserDTO;
import com.example.signin.Entity.UserEntity;
import com.example.signin.Repository.UserRepository;
import com.example.signin.Config.JWT.JwtTokenProvider;
import com.example.signin.Config.OAuthProperties.KakaoOAuthProperties;
import com.example.signin.Config.OAuthProperties.NaverOAuthProperties;
import com.example.signin.Config.OAuthProperties.GoogleOAuthProperties;
import com.example.signin.Config.OAuthProperties.FacebookOAuthProperties;
import com.example.signin.Config.OAuthProperties.GithubOAuthProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RestTemplate restTemplate;
    private final KakaoOAuthProperties kakaoOAuthProperties;
    private final NaverOAuthProperties naverOAuthProperties;
    private final GoogleOAuthProperties googleOAuthProperties;
    private final FacebookOAuthProperties facebookOAuthProperties;
    private final GithubOAuthProperties githubOAuthProperties;

    // 아이디 중복 확인
    @Override
    public boolean isUidDuplicate(String uid) {
        return userRepository.existsByUid(uid);
    }

    // 닉네임 중복 확인
    @Override
    public boolean isNicknameDuplicate(String nickname) {
        return userRepository.existsByNickname(nickname);
    }

    // 회원가입
    @Override
    public UserDTO createUser(UserDTO userDTO) {
        if (isUidDuplicate(userDTO.getUid())) {
            throw new IllegalArgumentException("중복된 아이디가 존재합니다");
        } else if (isNicknameDuplicate(userDTO.getNickname())) {
            throw new IllegalArgumentException("중복된 닉네임이 존재합니다");
        }
        UserEntity userEntity = userDTO.dtoToEntity();
        userEntity.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        userEntity.setProvider("normal");
        UserEntity savedUser = userRepository.save(userEntity);
        logger.info("회원가입 완료! " + userEntity);
        return UserDTO.entityToDto(savedUser);
    }

    // 로그인
    public JWTDTO login(String uid, String password) {
        UserEntity userEntity = userRepository.findByUid(uid).orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다"));
        if (!passwordEncoder.matches(password, userEntity.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다");
        }
        String token = jwtTokenProvider.generateToken(uid);
        logger.info("로그인 성공! 새로운 토큰이 발급되었습니다");
        return new JWTDTO(token, UserDTO.entityToDto(userEntity));
    }

    // 유저 전체 조회
    public List<UserDTO> getAllUser(String uid, UserDetails userDetails) {
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        return userRepository.findAll()
                .stream()
                .map(UserDTO::entityToDto)
                .collect(Collectors.toList());
    }

    // uid로 유저 조회
    @Override
    public UserDTO getUserByUid(String uid, UserDetails userDetails) {
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        UserEntity userEntity = userRepository.findByUid(uid).orElseThrow(() -> new RuntimeException("유저의 uid가 " + uid + "인 사용자를 찾을 수 없습니다"));
        return UserDTO.entityToDto(userEntity);
    }

    // 닉네임으로 유저 조회
    @Override
    public UserDTO getUserByNickname(String uid, String nickname, UserDetails userDetails){
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        UserEntity userEntity = userRepository.findByNickname(nickname).orElseThrow(() -> new RuntimeException("유저의 닉네임이 " + nickname + "인 사용자를 찾을 수 없습니다"));
        return UserDTO.entityToDto(userEntity);
    }

    // 닉네임 검색으로 유저 조회
    @Override
    public List<UserDTO> searchUserByNickname(String uid, String nickname, UserDetails userDetails){
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        return userRepository.findByNicknameContainingIgnoreCase(nickname)
                .stream()
                .map(UserDTO::entityToDto)
                .collect(Collectors.toList());
    }

    // 회원 정보 수정
    @Override
    public UserDTO updateUser(String uid, UserDTO userDTO, UserDetails userDetails) {
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        UserEntity userEntity = userRepository.findByUid(uid).orElseThrow(() -> new RuntimeException("유저의 uid가 " + uid + "인 사용자를 찾을 수 없습니다"));
        if (userDTO.getPassword() != null) {
            userEntity.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        }
        if (userDTO.getNickname() != null) {
            userEntity.setNickname(userDTO.getNickname());
        }
        UserEntity updatedUser = userRepository.save(userEntity);
        logger.info("사용자 정보 업데이트 완료! " + updatedUser);
        return UserDTO.entityToDto(updatedUser);
    }

    // 회원 탈퇴
    @Override
    public UserDTO deleteUser(String uid, UserDetails userDetails) {
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        UserEntity userEntity = userRepository.findByUid(uid).orElseThrow(() -> new RuntimeException("유저의 uid가 " + uid + "인 사용자를 찾을 수 없습니다"));
        userRepository.delete(userEntity);
        logger.info("유저의 uid가 " + uid + "인 회원탈퇴 완료!");
        return UserDTO.entityToDto(userEntity);
    }

    // 토큰 유효 시간 확인
    @Override
    public Long getTokenRemainingTime(UserDetails userDetails) {
        String uid = userDetails.getUsername();
        String token = jwtTokenProvider.getActiveToken(uid);
        if (token == null || jwtTokenProvider.isTokenInvalid(token)) {
            throw new IllegalArgumentException("유효하지 않거나 만료된 토큰입니다");
        }
        return jwtTokenProvider.getTokenRemainingTime(token);
    }

    // 토큰 연장 (오류나는 중)
    @Override
    public Long refreshToken(UserDetails userDetails) {
        String uid = userDetails.getUsername();
        String token = jwtTokenProvider.getActiveToken(uid);
        if (token == null) {
            throw new RuntimeException("활성화된 토큰이 없습니다.");
        }
        jwtTokenProvider.refreshToken(token);
        return jwtTokenProvider.getTokenRemainingTime(token);
    }

    // 유저 토큰 정보 조회
    @Override
    public JWTDTO getUserWithTokenInfo(String uid, String token, UserDetails userDetails) {
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        UserEntity userEntity = userRepository.findByUid(uid).orElseThrow(() -> new RuntimeException("유저의 uid가 " + uid + "인 사용자를 찾을 수 없습니다"));
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        Long remainingTime = jwtTokenProvider.getTokenRemainingTime(token);
        return new JWTDTO(token, UserDTO.entityToDto(userEntity), remainingTime);
    }

    // 닉네임 수정
    @Override
    public UserDTO updateNickname(String uid, String nickname, UserDetails userDetails) {
        if (!userDetails.getUsername().equals(uid)) {
            throw new RuntimeException("권한이 없습니다");
        }
        UserEntity userEntity = userRepository.findByUid(uid).orElseThrow(() -> new RuntimeException("유저의 uid가 " + uid + "인 사용자를 찾을 수 없습니다"));
        userEntity.setNickname(nickname);
        UserEntity updatedUser = userRepository.save(userEntity);
        logger.info("사용자 닉네임 업데이트 완료! " + updatedUser);
        return UserDTO.entityToDto(updatedUser);
    }

    // 닉네임 랜덤 생성
    private String randomNickname() {
        String[] A = {"멋진", "용감한", "빠른", "슬기로운", "조용한", "기분좋은", "귀여운", "신비로운", "재밌는", "상큼한", "활기찬", "따뜻한", "멋진", "반짝이는"};
        String[] B = {"사자", "호랑이", "사슴", "독수리", "나무늘보", "고양이", "토끼", "강아지", "부엉이", "너구리", "햄스터", "다람쥐", "펭귄", "고슴도치"};
        Random random = new Random();
        String adjective = A[random.nextInt(A.length)];
        String noun = B[random.nextInt(B.length)];
        return adjective + noun;
    }

    // 카카오 로그인 URL 값 확인
    @PostConstruct
    public void logKakaoOAuthSettings() {
        logger.info("카카오 로그인 설정 값 - clientId : {}, clientSecret : {}, redirectUri : {}",
                kakaoOAuthProperties.getClientId(),
                kakaoOAuthProperties.getClientSecret(),
                kakaoOAuthProperties.getRedirectUri());

        String authorizationUrl = String.format(
                "https://kauth.kakao.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code",
                kakaoOAuthProperties.getClientId(),
                kakaoOAuthProperties.getRedirectUri()
        );
        logger.info("카카오 로그인 URL : {}", authorizationUrl);
    }

    // 네이버 로그인 URL 값 확인
    @PostConstruct
    public void logNaverOAuthSettings(){
        logger.info("네이버 로그인 설정 값 - clientId : {}, clientSecret : {}, redirectUri : {}",
                naverOAuthProperties.getClientId(),
                naverOAuthProperties.getClientSecret(),
                naverOAuthProperties.getRedirectUri());

        String authorizationUrl = String.format(
                "https://nid.naver.com/oauth2.0/authorize?client_id=%s&redirect_uri=%s&response_type=code",
                naverOAuthProperties.getClientId(),
                naverOAuthProperties.getRedirectUri()
        );
        logger.info("네이버 로그인 URL : {}", authorizationUrl);
    }

    // 구글 로그인 URL 값 확인
    @PostConstruct
    public void logGoogleOAuthSettings(){
        logger.info("구글 로그인 설정 값 - clientId : {}, clientSecret : {}, redirectUri : {}",
                googleOAuthProperties.getClientId(),
                googleOAuthProperties.getClientSecret(),
                googleOAuthProperties.getRedirectUri());

        String authorizationUrl = String.format(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email%%20profile",
                googleOAuthProperties.getClientId(),
                googleOAuthProperties.getRedirectUri()
        );
        logger.info("구글 로그인 URL : {}", authorizationUrl);
    }

    // 페이스북 로그인 URL 값 확인
    @PostConstruct
    public void logFacebookOAuthSettings(){
        logger.info("페이스북 로그인 설정 값 - clientId : {}, clientSecret : {}, redirectUri : {}",
                facebookOAuthProperties.getClientId(),
                facebookOAuthProperties.getClientSecret(),
                facebookOAuthProperties.getRedirectUri());

        String authorizationUrl = String.format(
                "https://www.facebook.com/v12.0/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=code",
                facebookOAuthProperties.getClientId(),
                facebookOAuthProperties.getRedirectUri()
        );
        logger.info("페이스북 로그인 URL : {}", authorizationUrl);
    }

    // 깃허브 로그인 URL 값 확인
    @PostConstruct
    public void logGithubOAuthSettings(){
        logger.info("깃허브 로그인 설정 값 - clientId : {}, clientSecret : {}, redirectUri : {}",
                githubOAuthProperties.getClientId(),
                githubOAuthProperties.getClientSecret(),
                githubOAuthProperties.getRedirectUri());

        String authorizationUrl = String.format(
                "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user",
                githubOAuthProperties.getClientId(),
                githubOAuthProperties.getRedirectUri()
        );
        logger.info("깃허브 로그인 URL : {}", authorizationUrl);
    }

    // 카카오 인가 코드로 액세스 토큰 요청
    public String getKakaoAccessToken(String code) {
        String url = "https://kauth.kakao.com/oauth/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", kakaoOAuthProperties.getClientId());
        params.add("redirect_uri", kakaoOAuthProperties.getRedirectUri());
        params.add("code", code);
        params.add("client_secret", kakaoOAuthProperties.getClientSecret());

        logger.info("액세스 토큰 요청 URL : {}", url);
        logger.info("액세스 토큰 요청 헤더 : {}", headers);
        logger.info("액세스 토큰 요청 파라미터 : {}", params);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                String accessToken = (String) responseBody.get("access_token");
                logger.info("액세스 토큰을 성공적으로 가져왔습니다 : {}", accessToken);
                return accessToken;
            } else {
                logger.error("액세스 토큰을 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("액세스 토큰을 가져오는 중 오류가 발생하였습니다. (위치: getAccessToken ) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getAccessToken) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 액세스 토큰으로 사용자 정보 요청
    public Map<String, Object> getKakaoUserInfo(String accessToken) {
        String url = "https://kapi.kakao.com/v2/user/me";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                logger.info("사용자 정보를 성공적으로 가져왔습니다 : {}", responseBody);
                return responseBody;
            } else {
                logger.error("사용자 정보를 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("사용자 정보를 가져오는 중 오류가 발생했습니다. (위치: getUserInfo) : {}", e.getMessage());
            logger.error("응답 본문 (위치 : getUserInfo) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 카카오 로그인 처리
    @Override
    public JWTDTO loginWithKakaoOAuth2(String code) {
        try {
            String accessToken = getKakaoAccessToken(code);
            Map<String, Object> userInfo = getKakaoUserInfo(accessToken);

            String uid = String.valueOf(userInfo.get("id"));
            if (uid == null) {
                throw new RuntimeException("사용자 ID를 가져올 수 없습니다.");
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> properties = (Map<String, Object>) userInfo.get("properties");
            @SuppressWarnings("unchecked")
            Map<String, Object> kakaoAccount = (Map<String, Object>) userInfo.get("kakao_account");

            String name = null;
            if (properties != null) {
                name = (String) properties.get("nickname");
            }
            if (name == null) {
                name = "카카오사용자";
            }

            String email = null;
            if (kakaoAccount != null) {
                email = (String) kakaoAccount.get("email");
            }
            if (email == null) {
                throw new RuntimeException("사용자 이메일을 가져올 수 없습니다.");
            }

            UserEntity userEntity = userRepository.findByUid(uid).orElse(null);

            boolean isNewUser = false;
            if (userEntity == null) {
                userEntity = UserEntity.builder()
                        .uid(uid)
                        .name(name)
                        .email(email)
                        .password(passwordEncoder.encode("oauth2user"))
                        .provider("kakao")
                        .build();
                userRepository.save(userEntity);
                isNewUser = true;
            } else {
                userEntity.setName(name);
                userEntity.setEmail(email);
                userRepository.save(userEntity);
            }

            String token = jwtTokenProvider.generateToken(uid);
            logger.info("카카오 로그인 성공! 새로운 토큰이 발급되었습니다");
            return new JWTDTO(token, UserDTO.entityToDto(userEntity));
        } catch (HttpClientErrorException e) {
            logger.error("카카오 API 호출 중 오류가 발생했습니다 : {}", e.getMessage());
            logger.error("응답 본문: {}", e.getResponseBodyAsString());
            throw new RuntimeException("카카오 API 호출 중 오류가 발생했습니다.", e);
        } catch (Exception e) {
            logger.error("카카오 로그인 중 오류가 발생했습니다 (위치 : loginWithOAuth2) : {}", e.getMessage());
            throw new RuntimeException("카카오 로그인 중 오류가 발생했습니다. (위치 : loginWithOAuth2)", e);
        }
    }

    // 네이버 인가 코드로 액세스 토큰 요청
    public String getNaverAccessToken(String code) {
        String url = "https://nid.naver.com/oauth2.0/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", naverOAuthProperties.getClientId());
        params.add("client_secret", naverOAuthProperties.getClientSecret());
        params.add("redirect_uri", naverOAuthProperties.getRedirectUri());
        params.add("code", code);

        logger.info("액세스 토큰 요청 URL : {}", url);
        logger.info("액세스 토큰 요청 헤더 : {}", headers);
        logger.info("액세스 토큰 요청 파라미터 : {}", params);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                String accessToken = (String) responseBody.get("access_token");
                logger.info("액세스 토큰을 성공적으로 가져왔습니다 : {}", accessToken);
                return accessToken;
            } else {
                logger.error("액세스 토큰을 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("액세스 토큰을 가져오는 중 오류가 발생하였습니다. (위치: getNaverAccessToken) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getNaverAccessToken) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 액세스 토큰으로 사용자 정보 요청
    public Map<String, Object> getNaverUserInfo(String accessToken) {
        String url = "https://openapi.naver.com/v1/nid/me";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        logger.info("사용자 정보 요청 URL : {}", url);
        logger.info("사용자 정보 요청 헤더 : {}", headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                logger.info("사용자 정보를 성공적으로 가져왔습니다 : {}", responseBody);
                return responseBody;
            } else {
                logger.error("사용자 정보를 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("사용자 정보를 가져오는 중 오류가 발생했습니다. (위치: getNaverUserInfo) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getNaverUserInfo) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 네이버 로그인 처리
    @Override
    public JWTDTO loginWithNaverOAuth2(String code) {
        try {
            String accessToken = getNaverAccessToken(code);
            Map<String, Object> userInfo = getNaverUserInfo(accessToken);

            Map<String, Object> response = (Map<String, Object>) userInfo.get("response");
            String uid = (String) response.get("id");
            String name = (String) response.get("name");
            String email = (String) response.get("email");

            if (uid == null || name == null || email == null) {
                throw new RuntimeException("필수 사용자 정보를 가져올 수 없습니다.");
            }

            Optional<UserEntity> userEntityOptional = userRepository.findByUid(uid);
            UserEntity userEntity;
            if (userEntityOptional.isPresent()) {
                userEntity = userEntityOptional.get();
                userEntity.setName(name);
                userEntity.setEmail(email);
            } else {
                userEntity = UserEntity.builder()
                        .uid(uid)
                        .name(name)
                        .email(email)
                        .password(passwordEncoder.encode("OAuth2_User_Password"))
                        .provider("naver")
                        .build();
                userRepository.save(userEntity);
            }
            String token = jwtTokenProvider.generateToken(uid);
            logger.info("네이버 로그인 성공! 새로운 토큰이 발급되었습니다");
            return new JWTDTO(token, UserDTO.entityToDto(userEntity));
        } catch (HttpClientErrorException e) {
            logger.error("네이버 API 호출 중 오류가 발생했습니다 : {}", e.getMessage());
            logger.error("응답 본문 : {}", e.getResponseBodyAsString());
            throw new RuntimeException("네이버 API 호출 중 오류가 발생했습니다.", e);
        } catch (Exception e) {
            logger.error("네이버 로그인 중 오류가 발생했습니다 (위치 : loginWithNaverOAuth2) : {}", e.getMessage());
            throw new RuntimeException("네이버 로그인 중 오류가 발생했습니다. (위치 : loginWithNaverOAuth2)", e);
        }
    }

    // 구글 인가 코드로 액세스 토큰 요청
    public String getGoogleAccessToken(String code) {
        String url = "https://oauth2.googleapis.com/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", googleOAuthProperties.getClientId());
        params.add("client_secret", googleOAuthProperties.getClientSecret());
        params.add("redirect_uri", googleOAuthProperties.getRedirectUri());
        params.add("code", code);

        logger.info("액세스 토큰 요청 URL : {}", url);
        logger.info("액세스 토큰 요청 헤더 : {}", headers);
        logger.info("액세스 토큰 요청 파라미터 : {}", params);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                String accessToken = (String) responseBody.get("access_token");
                logger.info("액세스 토큰을 성공적으로 가져왔습니다 : {}", accessToken);
                return accessToken;
            } else {
                logger.error("액세스 토큰을 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("액세스 토큰을 가져오는 중 오류가 발생하였습니다. (위치: getGoogleAccessToken) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getGoogleAccessToken) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 액세스 토큰으로 사용자 정보 요청
    public Map<String, Object> getGoogleUserInfo(String accessToken) {
        String url = "https://www.googleapis.com/oauth2/v3/userinfo";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        logger.info("사용자 정보 요청 URL : {}", url);
        logger.info("사용자 정보 요청 헤더 : {}", headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                logger.info("사용자 정보를 성공적으로 가져왔습니다 : {}", responseBody);
                return responseBody;
            } else {
                logger.error("사용자 정보를 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("사용자 정보를 가져오는 중 오류가 발생했습니다. (위치: getGoogleUserInfo) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getGoogleUserInfo) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 구글 로그인 처리
    @Override
    public JWTDTO loginWithGoogleOAuth2(String code) {
        try {
            String accessToken = getGoogleAccessToken(code);
            Map<String, Object> userInfo = getGoogleUserInfo(accessToken);

            String uid = (String) userInfo.get("sub");
            String name = (String) userInfo.get("name");
            String email = (String) userInfo.get("email");

            if (uid == null || name == null || email == null) {
                throw new RuntimeException("필수 사용자 정보를 가져올 수 없습니다.");
            }

            Optional<UserEntity> userEntityOptional = userRepository.findByUid(uid);
            UserEntity userEntity;
            if (userEntityOptional.isPresent()) {
                userEntity = userEntityOptional.get();
                userEntity.setName(name);
                userEntity.setEmail(email);
            } else {
                userEntity = UserEntity.builder()
                        .uid(uid)
                        .name(name)
                        .email(email)
                        .password(passwordEncoder.encode("OAuth2_User_Password"))
                        .provider("google")
                        .build();
                userRepository.save(userEntity);
            }

            String token = jwtTokenProvider.generateToken(uid);
            logger.info("구글 로그인 성공! 새로운 토큰이 발급되었습니다");
            return new JWTDTO(token, UserDTO.entityToDto(userEntity));
        } catch (HttpClientErrorException e) {
            logger.error("구글 API 호출 중 오류가 발생했습니다 : {}", e.getMessage());
            logger.error("응답 본문: {}", e.getResponseBodyAsString());
            throw new RuntimeException("구글 API 호출 중 오류가 발생했습니다.", e);
        } catch (Exception e) {
            logger.error("구글 로그인 중 오류가 발생했습니다 (위치 : loginWithGoogleOAuth2) : {}", e.getMessage());
            throw new RuntimeException("구글 로그인 중 오류가 발생했습니다. (위치 : loginWithGoogleOAuth2)", e);
        }
    }

    // 페이스북 인가 코드로 액세스 토큰 요청
    public String getFacebookAccessToken(String code) {
        String url = "https://graph.facebook.com/v10.0/oauth/access_token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", facebookOAuthProperties.getClientId());
        params.add("client_secret", facebookOAuthProperties.getClientSecret());
        params.add("redirect_uri", facebookOAuthProperties.getRedirectUri());
        params.add("code", code);

        logger.info("액세스 토큰 요청 URL : {}", url);
        logger.info("액세스 토큰 요청 헤더 : {}", headers);
        logger.info("액세스 토큰 요청 파라미터 : {}", params);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                String accessToken = (String) responseBody.get("access_token");
                logger.info("액세스 토큰을 성공적으로 가져왔습니다 : {}", accessToken);
                return accessToken;
            } else {
                logger.error("액세스 토큰을 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("액세스 토큰을 가져오는 중 오류가 발생하였습니다. (위치: getFacebookAccessToken) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getFacebookAccessToken) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 액세스 토큰으로 사용자 정보 요청
    public Map<String, Object> getFacebookUserInfo(String accessToken) {
        String url = "https://graph.facebook.com/me?fields=id,name,email";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        logger.info("사용자 정보 요청 URL : {}", url);
        logger.info("사용자 정보 요청 헤더 : {}", headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                logger.info("사용자 정보를 성공적으로 가져왔습니다 : {}", responseBody);
                return responseBody;
            } else {
                logger.error("사용자 정보를 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("사용자 정보를 가져오는 중 오류가 발생했습니다. (위치: getFacebookUserInfo) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getFacebookUserInfo) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 페이스북 로그인 처리
    @Override
    public JWTDTO loginWithFacebookOAuth2(String code) {
        try {
            String accessToken = getFacebookAccessToken(code);
            Map<String, Object> userInfo = getFacebookUserInfo(accessToken);

            String uid = (String) userInfo.get("id");
            String name = (String) userInfo.get("name");
            String email = (String) userInfo.get("email");

            if (uid == null || name == null || email == null) {
                throw new RuntimeException("필수 사용자 정보를 가져올 수 없습니다.");
            }

            Optional<UserEntity> userEntityOptional = userRepository.findByUid(uid);
            UserEntity userEntity;
            if (userEntityOptional.isPresent()) {
                userEntity = userEntityOptional.get();
                userEntity.setName(name);
                userEntity.setEmail(email);
            } else {
                userEntity = UserEntity.builder()
                        .uid(uid)
                        .name(name)
                        .email(email)
                        .password(passwordEncoder.encode("OAuth2_User_Password"))
                        .provider("facebook")
                        .build();
                userRepository.save(userEntity);
            }

            String token = jwtTokenProvider.generateToken(uid);
            logger.info("페이스북 로그인 성공! 새로운 토큰이 발급되었습니다");
            return new JWTDTO(token, UserDTO.entityToDto(userEntity));
        } catch (HttpClientErrorException e) {
            logger.error("페이스북 API 호출 중 오류가 발생했습니다 : {}", e.getMessage());
            logger.error("응답 본문: {}", e.getResponseBodyAsString());
            throw new RuntimeException("페이스북 API 호출 중 오류가 발생했습니다.", e);
        } catch (Exception e) {
            logger.error("페이스북 로그인 중 오류가 발생했습니다 (위치 : loginWithFacebookOAuth2) : {}", e.getMessage());
            throw new RuntimeException("페이스북 로그인 중 오류가 발생했습니다. (위치 : loginWithFacebookOAuth2)", e);
        }
    }

    // 깃허브 인가 코드로 액세스 토큰 요청
    public String getGithubAccessToken(String code) {
        String url = "https://github.com/login/oauth/access_token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Accept", "application/json");
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", githubOAuthProperties.getClientId());
        params.add("client_secret", githubOAuthProperties.getClientSecret());
        params.add("redirect_uri", githubOAuthProperties.getRedirectUri());
        params.add("code", code);

        logger.info("액세스 토큰 요청 URL : {}", url);
        logger.info("액세스 토큰 요청 헤더 : {}", headers);
        logger.info("액세스 토큰 요청 파라미터 : {}", params);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                String accessToken = (String) responseBody.get("access_token");
                logger.info("액세스 토큰을 성공적으로 가져왔습니다 : {}", accessToken);
                return accessToken;
            } else {
                logger.error("액세스 토큰을 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("액세스 토큰을 가져오는 중 오류가 발생하였습니다. (위치: getGithubAccessToken) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getGithubAccessToken) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 액세스 토큰으로 사용자 정보 요청
    public Map<String, Object> getGithubUserInfo(String accessToken) {
        String url = "https://api.github.com/user";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        logger.info("사용자 정보 요청 URL : {}", url);
        logger.info("사용자 정보 요청 헤더 : {}", headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null) {
                logger.info("사용자 정보를 성공적으로 가져왔습니다 : {}", responseBody);
                return responseBody;
            } else {
                logger.error("사용자 정보를 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
                return null;
            }
        } catch (HttpClientErrorException e) {
            logger.error("사용자 정보를 가져오는 중 오류가 발생했습니다. (위치: getGithubUserInfo) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getGithubUserInfo) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 사용자 이메일 추가 요청
    public String getGithubUserEmail(String accessToken) {
        String url = "https://api.github.com/user/emails";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        logger.info("사용자 이메일 요청 URL : {}", url);
        logger.info("사용자 이메일 요청 헤더 : {}", headers);

        try {
            ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, entity, List.class);
            List<Map<String, Object>> emails = response.getBody();
            if (emails != null) {
                for (Map<String, Object> emailData : emails) {
                    Boolean primary = (Boolean) emailData.get("primary");
                    Boolean verified = (Boolean) emailData.get("verified");
                    String email = (String) emailData.get("email");
                    if (primary != null && primary && verified != null && verified) {
                        logger.info("사용자 이메일을 성공적으로 가져왔습니다 : {}", email);
                        return email;
                    }
                }
            }
            logger.error("사용자 이메일을 가져오는데 실패했습니다. 응답 본문이 비어있습니다.");
            return null;
        } catch (HttpClientErrorException e) {
            logger.error("사용자 이메일을 가져오는 중 오류가 발생했습니다. (위치: getGithubUserEmail) : {}", e.getMessage());
            logger.error("응답 본문 (위치: getGithubUserEmail) : {}", e.getResponseBodyAsString());
            throw e;
        }
    }

    // 깃허브 로그인 처리
    @Override
    public JWTDTO loginWithGithubOAuth2(String code) {
        try {
            String accessToken = getGithubAccessToken(code);
            Map<String, Object> userInfo = getGithubUserInfo(accessToken);
            String email = getGithubUserEmail(accessToken);

            String uid = String.valueOf(userInfo.get("id"));
            String name = (String) userInfo.get("name");
            if (uid == null || name == null || email == null) {
                throw new RuntimeException("필수 사용자 정보를 가져올 수 없습니다.");
            }

            Optional<UserEntity> userEntityOptional = userRepository.findByUid(uid);
            UserEntity userEntity;
            if (userEntityOptional.isPresent()) {
                userEntity = userEntityOptional.get();
                userEntity.setName(name);
                userEntity.setEmail(email);
            } else {
                userEntity = UserEntity.builder()
                        .uid(uid)
                        .name(name)
                        .email(email)
                        .password(passwordEncoder.encode("OAuth2_User_Password"))
                        .provider("github")
                        .build();
                userRepository.save(userEntity);
            }

            String token = jwtTokenProvider.generateToken(uid);
            logger.info("깃허브 로그인 성공! 새로운 토큰이 발급되었습니다");
            return new JWTDTO(token, UserDTO.entityToDto(userEntity));
        } catch (HttpClientErrorException e) {
            logger.error("깃허브 API 호출 중 오류가 발생했습니다: {}", e.getMessage());
            logger.error("응답 본문 : {}", e.getResponseBodyAsString());
            throw new RuntimeException("깃허브 API 호출 중 오류가 발생했습니다.", e);
        } catch (Exception e) {
            logger.error("깃허브 로그인 중 오류가 발생했습니다 (위치 : loginWithGithubOAuth2) : {}", e.getMessage());
            throw new RuntimeException("깃허브 로그인 중 오류가 발생했습니다. (위치 : loginWithGithubOAuth2)", e);
        }
    }
}


