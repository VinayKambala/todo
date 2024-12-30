package com.todo.service;

import java.util.HashMap;
import java.util.Map;

public class UserService {
    private Map<Integer, User> userDatabase = new HashMap<>();

    // Method to get user details by ID
    public User getUserById(int userId) {
        return userDatabase.get(userId);
    }

    // Method to create a new user
    public void createUser(int userId, String userName) {
        User user = new User(userId, userName);
        userDatabase.put(userId, user);
    }

    // Method to update user details
    public void updateUser(int userId, String newUserName) {
        User user = userDatabase.get(userId);
        if (user != null) {
            user.setUserName(newUserName);
        }
    }

    // Method to delete a user
    public void deleteUser(int userId) {
        userDatabase.remove(userId);
    }

    // Inner User class
    public static class User {
        private int userId;
        private String userName;

        public User(int userId, String userName) {
            this.userId = userId;
            this.userName = userName;
        }

        public int getUserId() {
            return userId;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }
    }
}