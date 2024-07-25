package com.example.signin.Repository;

import com.example.signin.Entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUid(String uid);
    public UserEntity findByNickname(String nickname);
    boolean existsByUid(String uid);
    boolean existsByNickname(String nickname);
}

