package com.todo.service;

import com.todo.exception.TaskNotFoundException;
import com.todo.exception.TaskValidationException;
import com.todo.model.Task;
import com.todo.repository.TaskRepository;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@Transactional
public class TaskService {

    private final TaskRepository taskRepository;
    Logger log = LoggerFactory.getLogger(TaskService.class);

    @Autowired
    public TaskService(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public Task createTask(Task task) {
        validateTask(task);

        task.setCreatedDate(LocalDateTime.now());
        task.setLastModifiedDate(LocalDateTime.now());

        if (task.getPriority() == null) {
            task.setPriority(Task.Priority.MEDIUM);
        }

        log.info("Creating new task for user: {}", task.getUserId());
        return taskRepository.save(task);
    }

    @Cacheable(value = "tasks", key = "#id + '-' + #userId")
    @Transactional(readOnly = true)
    public Task getTaskById(String id, String userId) {
        return taskRepository.findByIdAndUserId(id, userId)
                .orElseThrow(() -> new TaskNotFoundException("Task not found with id: " + id));
    }

    @Cacheable(value = "userTasks", key = "#userId")
    @Transactional(readOnly = true)
    public List<Task> getUserTasks(String userId) {
        log.debug("Fetching all tasks for user: {}", userId);
        return taskRepository.findByUserId(userId);
    }


    @Transactional(readOnly = true)
    public List<Task> searchTasksByTitleAndCompletion(String userId, String title, boolean completed) {
        return taskRepository.findByUserIdAndTitleAndCompleted(userId, title, completed);
    }

    @CacheEvict(value = {"tasks", "userTasks"}, key = "#id + '-' + #userId")
    public Task updateTask(String id, Task updatedTask, String userId) {
        validateTask(updatedTask);
        Task existingTask = getTaskById(id, userId);

        updateTaskFields(existingTask, updatedTask);
        existingTask.setLastModifiedDate(LocalDateTime.now());

        log.info("Updating task: {} for user: {}", id, userId);
        return taskRepository.save(existingTask);
    }

    @CacheEvict(value = {"tasks", "userTasks"}, key = "#id + '-' + #userId")
    public void deleteTask(String id, String userId) {
        Task task = getTaskById(id, userId);
        log.info("Deleting task: {} for user: {}", id, userId);
        taskRepository.delete(task);
    }

    @Transactional(readOnly = true)
    public List<Task> searchTasks(String userId, String titleQuery) {
        if (!StringUtils.hasText(titleQuery)) {
            return getUserTasks(userId);
        }
        return taskRepository.findByUserIdAndTitleContainingIgnoreCase(userId, titleQuery);
    }

    @Transactional(readOnly = true)
    public List<Task> getTasksByStatus(String userId, boolean completed) {
        return taskRepository.findByUserIdAndCompleted(userId, completed);
    }

    @Transactional(readOnly = true)
    public List<Task> getTasksByPriority(String userId, Task.Priority priority) {
        return taskRepository.findByUserIdAndPriority(userId, priority);
    }

    @Transactional(readOnly = true)
    public List<Task> getOverdueTasks(String userId) {
        LocalDateTime now = LocalDateTime.now();
        return taskRepository.findOverdueTasks(userId, now)
                .stream()
                .filter(task -> !task.isCompleted())
                .collect(Collectors.toList());
    }

    @CacheEvict(value = "userTasks", key = "#userId")
    public void deleteCompletedTasks(String userId) {
        log.info("Deleting all completed tasks for user: {}", userId);
        taskRepository.deleteByUserIdAndCompleted(userId, true);
    }


    @CacheEvict(value = {"tasks", "userTasks"}, key = "#id + '-' + #userId")
    public Task toggleTaskCompletion(String id, String userId) {
        Task task = getTaskById(id, userId);
        task.setCompleted(!task.isCompleted());
        task.setLastModifiedDate(LocalDateTime.now());

        if (task.isCompleted()) {
            task.setCompletedDate(LocalDateTime.now());
        } else {
            task.setCompletedDate(null);
        }

        log.info("Toggling completion status for task: {} to: {}", id, task.isCompleted());
        return taskRepository.save(task);
    }

    @CacheEvict(value = "userTasks", key = "#userId")
    public void markAllTasksAsCompleted(String userId) {
        List<Task> tasks = getUserTasks(userId);
        LocalDateTime now = LocalDateTime.now();

        tasks.stream()
                .filter(task -> !task.isCompleted())
                .forEach(task -> {
                    task.setCompleted(true);
                    task.setCompletedDate(now);
                    task.setLastModifiedDate(now);
                });

        taskRepository.saveAll(tasks);
        log.info("Marked {} tasks as completed for user: {}", tasks.size(), userId);
    }

    private void validateTask(Task task) {
        if (task == null) {
            throw new TaskValidationException("Task cannot be null");
        }
        if (!StringUtils.hasText(task.getTitle())) {
            throw new TaskValidationException("Task title is required");
        }
        if (task.getTitle().length() > 100) {
            throw new TaskValidationException("Task title cannot exceed 100 characters");
        }
        if (task.getDescription() != null && task.getDescription().length() > 500) {
            throw new TaskValidationException("Task description cannot exceed 500 characters");
        }
    }

    private void updateTaskFields(Task existingTask, Task updatedTask) {
        existingTask.setTitle(updatedTask.getTitle());
        existingTask.setDescription(updatedTask.getDescription());
        existingTask.setCompleted(updatedTask.isCompleted());
        existingTask.setPriority(updatedTask.getPriority());
        existingTask.setDueDate(updatedTask.getDueDate());
        existingTask.setTags(updatedTask.getTags());
        existingTask.setCategory(updatedTask.getCategory());
        existingTask.setEstimatedMinutes(updatedTask.getEstimatedMinutes());

        if (updatedTask.isCompleted() && !existingTask.isCompleted()) {
            existingTask.setCompletedDate(LocalDateTime.now());
        } else if (!updatedTask.isCompleted()) {
            existingTask.setCompletedDate(null);
        }
    }
}

