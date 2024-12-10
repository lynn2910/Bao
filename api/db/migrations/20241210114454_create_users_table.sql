CREATE TABLE users
(
    id         CHAR(36)     NOT NULL,
    first_name VARCHAR(64)  NOT NULL,
    last_name  VARCHAR(64),
    password   CHAR(97)     NOT NULL,
    email      VARCHAR(320) NOT NULL UNIQUE,

    PRIMARY KEY (id)
);