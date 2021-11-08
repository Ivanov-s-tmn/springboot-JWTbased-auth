package com.example.personservice.service;

import com.example.personservice.model.Director;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import com.example.personservice.repository.DirectorRepository;

@Service
public class DirectorServiceImpl implements DirectorService {

    DirectorRepository directorRepository;

    @Autowired
    public void setDirectorRepository(DirectorRepository directorRepository) {
        this.directorRepository = directorRepository;
    }

    @Override
    public void addDirector(Director director) {
        directorRepository.save(director);

    }

    @Override
    public void updateDirector(Director director) {
        directorRepository.save(director);

    }

    @Override
    public void deleteDirectorById(long id) {
        directorRepository.deleteById(id);

    }

    @Override
    public Director getDirectorById(long id) {
        return directorRepository.getById(id);
    }

    @Override
    public Director getDirectorByFirstName(String name) {
        return directorRepository.findDirectorByFirstName(name);
    }

    @Override
    public List<Director> getAllDirectors() {
        return directorRepository.findAll();
    }
}
