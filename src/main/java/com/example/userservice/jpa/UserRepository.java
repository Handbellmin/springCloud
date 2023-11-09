package com.example.userservice.jpa;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<Users, Long>{
    Users findByEmail(String email);
    Users findByUserId(String userId);
}
