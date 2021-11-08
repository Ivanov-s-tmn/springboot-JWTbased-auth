package com.example.personservice.model;

import javax.persistence.*;
import java.util.Date;
import java.util.Set;

@Entity
public class Director extends Person {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column
    private Date startManagement;

    @Column
    private Date endManagement;

    @OneToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "director_school", joinColumns = @JoinColumn(name = "director_id"),
            inverseJoinColumns = @JoinColumn(name = "school_id"))
    private School school;

    public Director() {
    }

    public Director(School school, String firstName, String lastName, String secondName, char gender, int age) {
        super(firstName, lastName, secondName, gender, age);
        this.school = school;

    }

    public School getSchool() {
        return school;
    }

    public void setSchool(School school) {
        this.school = school;
    }

    public Date getStartManagement() {
        return startManagement;
    }

    public void setStartManagement(Date startManagement) {
        this.startManagement = startManagement;
    }

    public Date getEndManagement() {
        return endManagement;
    }

    public void setEndManagement(Date endManagement) {
        this.endManagement = endManagement;
    }


}
