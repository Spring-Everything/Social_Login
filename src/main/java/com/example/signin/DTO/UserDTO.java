package com.example.signin.DTO;

import com.example.signin.Entity.UserEntity;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class UserDTO {
    private Long id;
    private String uid;
    private String password;
    private String name;
    private String nickname;
    private String email;
    private String provider;

    public static UserDTO entityToDto(UserEntity userEntity) {
        return new UserDTO(
                userEntity.getId(),
                userEntity.getUid(),
                userEntity.getPassword(),
                userEntity.getName(),
                userEntity.getNickname(),
                userEntity.getEmail(),
                userEntity.getProvider()
        );
    }

    public UserEntity dtoToEntity() {
        return new UserEntity(id, uid, password, name, nickname, email, provider);
    }
}


