package com.jm.project.schooljournal.exception;

public class NotFoundException extends RuntimeException {

    public NotFoundException(int id) {
        super("User with id=" + id + " not found");
    }

    public NotFoundException(String name) {
        super("User with name=" + name + " not found");
    }
}

