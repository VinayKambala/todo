package com.todo.service;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TaskStatistics {
    private long totalTasks;
    private long completedTasks;
    private long overdueTasks;

    public double getCompletionRate() {
        return totalTasks == 0 ? 0 : (double) completedTasks / totalTasks * 100;
    }
}
