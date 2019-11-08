package com.grokonez.jwtauthentication.repository;

import com.grokonez.jwtauthentication.model.Role;
import com.grokonez.jwtauthentication.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    // Optional<Role> findByName(RoleName roleName);
    Optional<Role> findByName(RoleName role);
}