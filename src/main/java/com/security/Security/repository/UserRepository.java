package com.security.Security.repository;

import com.security.Security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import com.security.Security.entity.Role;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByEmail(String email);
    User findByRole(Role role);



}
