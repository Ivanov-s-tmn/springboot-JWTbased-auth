package com.example.personservice.model;

//TODO унаследовать от Person
//  Добавить связку родитель ученик (OneToMany)

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "parents")
public class Parent extends Person {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToMany(mappedBy = "id",
            fetch = FetchType.LAZY,
            cascade = CascadeType.ALL,
            orphanRemoval = true)
    private List<Student> studentsList;

    public Parent() {
    }

    public Parent(String firstName, String lastName, String secondName, char gender, int age, List studentsList) {
        super(firstName, lastName, secondName, gender, age);
        this.studentsList = studentsList;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public List<Student> getStudentsList() {
        return studentsList;
    }

    public void setStudentsList(List<Student> studentsList) {
        this.studentsList = studentsList;
    }

}
