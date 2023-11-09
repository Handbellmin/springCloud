package com.example.userservice.service;

import com.example.userservice.dto.UserDto;
import com.example.userservice.jpa.UserRepository;
import com.example.userservice.jpa.Users;
import com.example.userservice.vo.ResponseOrder;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = userRepository.findByEmail(username);
        if (users == null) throw new UsernameNotFoundException(username);

        return new User(users.getEmail(), users.getEncrytedPwd(),
                true, true, true, true,
                new ArrayList<>());
        // ArrayList -> 권한 추가 작업
    }

    final UserRepository userRepository;
    final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Override
    public UserDto createUser(UserDto userDto) {
        userDto.setUserId(UUID.randomUUID().toString());
        ModelMapper mapper = new ModelMapper();
        mapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
        Users users = mapper.map(userDto, Users.class);
        users.setEncrytedPwd(bCryptPasswordEncoder.encode(userDto.getPwd()));
        userRepository.save(users);
        UserDto dto = mapper.map(users, UserDto.class);
        return dto;
    }

    @Override
    public UserDto getUserByUserId(String userId) {
        Users users = userRepository.findByUserId(userId);

        if (users == null) throw new UsernameNotFoundException("User not found");
        UserDto userDto = new ModelMapper().map(users, UserDto.class);
        List<ResponseOrder> orders = new ArrayList<>();
        userDto.setOrders(orders);
        return userDto;
    }

    @Override
    public Iterable<Users> getUserByAll() {
        return userRepository.findAll();
    }

    @Override
    public UserDto getUserDetailsByEmail(String email) {
        Users users = userRepository.findByEmail(email);

        if (users == null)
            throw new UsernameNotFoundException(email);

        UserDto userDto = new ModelMapper().map(users, UserDto.class);
        return userDto;
    }
}
