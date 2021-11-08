package com.example.personservice.repository;

import com.example.personservice.model.Director;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DirectorRepository extends JpaRepository<Director, Long> {
    Director findDirectorByFirstName(String name);
}
