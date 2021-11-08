package com.jm.project.schooljournal.repository;

import com.jm.project.schooljournal.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findUserByUsername(String name);
}
