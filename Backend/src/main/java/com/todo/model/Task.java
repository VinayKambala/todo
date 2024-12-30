package com.todo.model;

import jakarta.validation.constraints.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.TextIndexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Document(collection = "tasks")
@CompoundIndexes({
        @CompoundIndex(name = "user_title_idx", def = "{'userId': 1, 'title': 1}"),
        @CompoundIndex(name = "user_completed_idx", def = "{'userId': 1, 'completed': 1}"),
        @CompoundIndex(name = "user_dueDate_idx", def = "{'userId': 1, 'dueDate': 1}"),
        @CompoundIndex(name = "user_priority_idx", def = "{'userId': 1, 'priority': 1}")
})
public class Task {

    @Id
    private String id;

    @Version
    private Long version;

    private String userId;

    @NotBlank(message = "Title is required")
    @Size(min = 1, max = 100, message = "Title must be between 1 and 100 characters")
    @TextIndexed
    private String title;

    @Size(max = 500, message = "Description cannot exceed 500 characters")
    @TextIndexed
    private String description;

    @NotNull(message = "Completion status is required")
    private boolean completed = false;

    @FutureOrPresent(message = "Due date must be in the present or future")
    private LocalDateTime dueDate;

    @NotNull
    @PastOrPresent
    @CreatedDate
    private LocalDateTime createdDate;

    @NotNull
    @PastOrPresent
    @LastModifiedDate
    private LocalDateTime lastModifiedDate;

    @NotNull
    private Priority priority = Priority.MEDIUM;

    private final List<String> tags = new ArrayList<>();


    @Size(max = 50, message = "Category name cannot exceed 50 characters")
    private String category;

    @Min(value = 1, message = "Estimated minutes must be at least 1")
    @Max(value = 480, message = "Estimated minutes must not exceed 480")
    private Integer estimatedMinutes;

    @PastOrPresent(message = "Completed date must be in the past or present")
    private LocalDateTime completedDate;

    private String parentTaskId;

    private final List<String> subtaskIds = new ArrayList<>();

    private boolean recurring;

    private RecurrencePattern recurrencePattern;

    public enum Priority {
        LOW, MEDIUM, HIGH, URGENT
    }

    public enum RecurrencePattern {
        DAILY, WEEKLY, MONTHLY, YEARLY, CUSTOM
    }

    // Default constructor
    public Task() {
        this.createdDate = LocalDateTime.now();
        this.lastModifiedDate = LocalDateTime.now();
    }

    // Constructor with required fields
    public Task(String userId, String title) {
        this();
        this.userId = userId;
        this.title = title;
    }

    // Copy constructor
    public Task(Task other) {
        this.userId = other.userId;
        this.title = other.title;
        this.description = other.description;
        this.completed = other.completed;
        this.dueDate = other.dueDate;
        this.priority = other.priority;
        this.tags.addAll(other.tags);
        this.category = other.category;
        this.estimatedMinutes = other.estimatedMinutes;
        this.parentTaskId = other.parentTaskId;
        this.subtaskIds.addAll(other.subtaskIds);
        this.recurring = other.recurring;
        this.recurrencePattern = other.recurrencePattern;
        this.createdDate = LocalDateTime.now();
        this.lastModifiedDate = LocalDateTime.now();
    }

    // Getters and Setters with null checks and validation
    public String getId() {
        return id;
    }

    protected void setId(String id) {
        this.id = id;
    }

    public Long getVersion() {
        return version;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null");
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = Objects.requireNonNull(title, "Title cannot be null").trim();
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description != null ? description.trim() : null;
    }

    public boolean isCompleted() {
        return completed;
    }

    public void setCompleted(boolean completed) {
        this.completed = completed;
        if (completed) {
            this.completedDate = LocalDateTime.now();
        } else {
            this.completedDate = null;
        }
    }

    public LocalDateTime getDueDate() {
        return dueDate;
    }

    public void setDueDate(LocalDateTime dueDate) {
        if (dueDate != null && dueDate.isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Due date cannot be in the past");
        }
        this.dueDate = dueDate;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(LocalDateTime createdDate) {
        this.createdDate = Objects.requireNonNull(createdDate);
    }

    public LocalDateTime getLastModifiedDate() {
        return lastModifiedDate;
    }

    public void setLastModifiedDate(LocalDateTime lastModifiedDate) {
        this.lastModifiedDate = Objects.requireNonNull(lastModifiedDate);
    }

    public Priority getPriority() {
        return priority;
    }

    public void setPriority(Priority priority) {
        this.priority = Objects.requireNonNull(priority, "Priority cannot be null");
    }

    public List<String> getTags() {
        return new ArrayList<>(tags);
    }

    public void setTags(List<String> tags) {
        this.tags.clear();
        if (tags != null) {
            this.tags.addAll(tags.stream()
                    .filter(Objects::nonNull)
                    .map(String::trim)
                    .filter(tag -> !tag.isEmpty())
                    .toList());
        }
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category != null ? category.trim() : null;
    }

    public Integer getEstimatedMinutes() {
        return estimatedMinutes;
    }

    public void setEstimatedMinutes(Integer estimatedMinutes) {
        if (estimatedMinutes != null && (estimatedMinutes < 1 || estimatedMinutes > 480)) {
            throw new IllegalArgumentException("Estimated minutes must be between 1 and 480");
        }
        this.estimatedMinutes = estimatedMinutes;
    }

    public LocalDateTime getCompletedDate() {
        return completedDate;
    }

    public void setCompletedDate(LocalDateTime completedDate) {
        this.completedDate = completedDate;
    }

    public String getParentTaskId() {
        return parentTaskId;
    }

    public void setParentTaskId(String parentTaskId) {
        this.parentTaskId = parentTaskId;
    }

    public List<String> getSubtaskIds() {
        return new ArrayList<>(subtaskIds);
    }

    public void setSubtaskIds(List<String> subtaskIds) {
        this.subtaskIds.clear();
        if (subtaskIds != null) {
            this.subtaskIds.addAll(subtaskIds);
        }
    }

    public boolean isRecurring() {
        return recurring;
    }

    public void setRecurring(boolean recurring) {
        this.recurring = recurring;
    }

    public RecurrencePattern getRecurrencePattern() {
        return recurrencePattern;
    }

    public void setRecurrencePattern(RecurrencePattern recurrencePattern) {
        this.recurrencePattern = recurrencePattern;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Task task)) return false;
        return Objects.equals(id, task.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Task{" +
                "id='" + id + '\'' +
                ", userId='" + userId + '\'' +
                ", title='" + title + '\'' +
                ", completed=" + completed +
                ", dueDate=" + dueDate +
                ", priority=" + priority +
                ", category='" + category + '\'' +
                ", recurring=" + recurring +
                '}';
    }
}