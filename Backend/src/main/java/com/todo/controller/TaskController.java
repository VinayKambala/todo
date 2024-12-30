package com.todo.controller;

import com.todo.exception.TaskNotFoundException;
import com.todo.exception.UnauthorizedAccessException;
import com.todo.model.Task;
import com.todo.service.AuthService;
import com.todo.service.TaskService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/tasks")
@Slf4j
@Validated
public class TaskController {
    private final TaskService taskService;
    private final AuthService authService;

    @Autowired
    public TaskController(TaskService taskService, AuthService authService) {
        this.taskService = taskService;
        this.authService = authService;

    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<Task> createTask(
            @RequestHeader("Authorization") String token,
            @Valid @RequestBody Task task) {
        String userId = getUserIdFromToken(token);
        task.setUserId(userId);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(taskService.createTask(task));
    }

    @GetMapping
    public ResponseEntity<List<Task>> getTasks(@RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        List<Task> tasks = taskService.getUserTasks(userId);
        return ResponseEntity.ok(tasks);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Task> getTaskById(
            @PathVariable String id,
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        return ResponseEntity.ok(taskService.getTaskById(id, userId));
    }

    @PutMapping("/{id}")
    public ResponseEntity<Task> updateTask(
            @PathVariable String id,
            @Valid @RequestBody Task task,
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        return ResponseEntity.ok(taskService.updateTask(id, task, userId));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteTask(
            @PathVariable String id,
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        taskService.deleteTask(id, userId);
    }

    @GetMapping("/search")
    public ResponseEntity<List<Task>> searchTasks(
            @RequestHeader("Authorization") String token,
            @RequestParam(required = false) String title,
            @RequestParam(required = false) Boolean completed,
            @RequestParam(required = false) Task.Priority priority) {
        String userId = getUserIdFromToken(token);
        List<Task> tasks;

        if (priority != null) {
            tasks = taskService.getTasksByPriority(userId, priority);
        } else if (title != null && completed != null) {
            tasks = taskService.searchTasksByTitleAndCompletion(userId, title, completed);
        } else if (title != null) {
            tasks = taskService.searchTasks(userId, title);
        } else if (completed != null) {
            tasks = taskService.getTasksByStatus(userId, completed);
        } else {
            tasks = taskService.getUserTasks(userId);
        }
        return ResponseEntity.ok(tasks);
    }

    @GetMapping("/overdue")
    public ResponseEntity<List<Task>> getOverdueTasks(
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        return ResponseEntity.ok(taskService.getOverdueTasks(userId));
    }

    @PatchMapping("/{id}/toggle")
    public ResponseEntity<Task> toggleTaskCompletion(
            @PathVariable String id,
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        return ResponseEntity.ok(taskService.toggleTaskCompletion(id, userId));
    }

    @PostMapping("/complete-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void markAllTasksAsCompleted(
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        taskService.markAllTasksAsCompleted(userId);
    }

    @DeleteMapping("/completed")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteCompletedTasks(
            @RequestHeader("Authorization") String token) {
        String userId = getUserIdFromToken(token);
        taskService.deleteCompletedTasks(userId);
    }

    private String getUserIdFromToken(String token) {
        return authService.validateToken(token.replace("Bearer ", ""));
    }

    @ExceptionHandler(TaskNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<ErrorResponse> handleTaskNotFound(TaskNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(UnauthorizedAccessException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<ErrorResponse> handleUnauthorizedAccess(UnauthorizedAccessException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorResponse(ex.getMessage()));
    }
}

// DTO classes
class PageResponse<T> {
    private List<T> content;
    private int pageNumber;
    private int pageSize;
    private long totalElements;
    private int totalPages;

    public PageResponse(Page<T> page) {
        this.content = page.getContent();
        this.pageNumber = page.getNumber();
        this.pageSize = page.getSize();
        this.totalElements = page.getTotalElements();
        this.totalPages = page.getTotalPages();
    }

    // Getters
}

class ErrorResponse {
    private final String message;
    private final long timestamp;

    public ErrorResponse(String message) {
        this.message = message;
        this.timestamp = System.currentTimeMillis();
    }

    // Getters
}