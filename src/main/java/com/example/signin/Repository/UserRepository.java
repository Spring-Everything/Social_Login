package com.example.signin.Repository;

import com.example.signin.Entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    boolean existsByUid(String uid);
    boolean existsByNickname(String nickname);
    Optional<UserEntity> findByUid(String uid);
    Optional<UserEntity> findByNickname(String nickname);
    Optional<UserEntity> findByNicknameContainingIgnoreCase(String nickname);
}

