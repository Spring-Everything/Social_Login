package com.example.signin.Config.OAuthProperties;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.client.registration.github")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class GithubOAuthProperties {
    private String clientId;
    private String clientSecret;
    private String redirectUri;
}

