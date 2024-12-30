package com.todo.repository;

import com.todo.model.Task;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface TaskRepository extends MongoRepository<Task, String> {

    // Basic CRUD with user context
    @Query("{ 'userId': ?0 }")
    List<Task> findByUserId(String userId);

    @Query("{ '_id': ?0, 'userId': ?1 }")
    Optional<Task> findByIdAndUserId(String id, String userId);

    // Task status queries
    @Query("{ 'userId': ?0, 'completed': ?1 }")
    List<Task> findByUserIdAndCompleted(String userId, boolean completed);

    // Search queries
    @Query("{ 'userId': ?0, 'title': { $regex: ?1, $options: 'i' } }")
    List<Task> findByUserIdAndTitleContainingIgnoreCase(String userId, String title);

    @Query("{ 'userId': ?0, 'title': { $regex: ?1, $options: 'i' }, 'completed': ?2 }")
    List<Task> findByUserIdAndTitleAndCompleted(String userId, String title, boolean completed);

    // Priority and due date queries
    @Query("{ 'userId': ?0, 'priority': ?1 }")
    List<Task> findByUserIdAndPriority(String userId, Task.Priority priority);

    @Query("{ 'userId': ?0, 'dueDate': { $lt: ?1 }, 'completed': false }")
    List<Task> findOverdueTasks(String userId, LocalDateTime now);

    // Pagination support for large datasets
    @Query("{ 'userId': ?0 }")
    List<Task> findAllByUserId(String userId);

    // Analytics queries
    @Query(value = "{ 'userId': ?0, 'completed': true }", count = true)
    long countCompletedTasksByUser(String userId);

    @Query(value = "{ 'userId': ?0}", count = true)
    long countByUserId(String userId);

    // Bulk operations
    void deleteByUserIdAndCompleted(String userId, boolean completed);
}
