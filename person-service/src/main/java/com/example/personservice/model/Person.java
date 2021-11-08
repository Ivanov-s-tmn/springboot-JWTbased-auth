package com.example.personservice.model;

public abstract class Person {

    private String firstName;
    private String lastName;
    private String secondName;
    private char gender;
    private int age;

    public Person(String firstName, String lastName, String secondName, char gender, int age) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.secondName = secondName;
        this.gender = gender;
        this.age = age;
    }

    public Person() {
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getSecondName() {
        return secondName;
    }

    public void setSecondName(String secondName) {
        this.secondName = secondName;
    }

    public char getGender() {
        return gender;
    }

    public void setGender(char gender) {
        this.gender = gender;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}
