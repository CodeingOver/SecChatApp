-- ============================================
-- SecChatApp Database Setup Script
-- Run this in SQL Server Management Studio (SSMS)
-- ============================================

-- Create database
IF NOT EXISTS (SELECT name
FROM sys.databases
WHERE name = N'SecChatDB')
BEGIN
    CREATE DATABASE SecChatDB;
END
GO

USE SecChatDB;
GO

-- Users table
IF NOT EXISTS (SELECT *
FROM sys.tables
WHERE name = 'Users')
BEGIN
    CREATE TABLE Users
    (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Username NVARCHAR(20) NOT NULL UNIQUE,
        PasswordHash NVARCHAR(128) NOT NULL,
        Salt NVARCHAR(32) NOT NULL,
        CreatedAt DATETIME2 DEFAULT GETDATE()
    );
    CREATE UNIQUE INDEX IX_Users_Username ON Users(Username);
END
GO

-- Sessions table
IF NOT EXISTS (SELECT *
FROM sys.tables
WHERE name = 'Sessions')
BEGIN
    CREATE TABLE Sessions
    (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Token NVARCHAR(64) NOT NULL UNIQUE,
        Username NVARCHAR(20) NOT NULL,
        CreatedAt DATETIME2 DEFAULT GETDATE(),
        CONSTRAINT FK_Sessions_Users FOREIGN KEY (Username) REFERENCES Users(Username)
    );
    CREATE UNIQUE INDEX IX_Sessions_Token ON Sessions(Token);
END
GO

-- Messages table (luu tru lich su tin nhan)
IF NOT EXISTS (SELECT *
FROM sys.tables
WHERE name = 'Messages')
BEGIN
    CREATE TABLE Messages
    (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        FromUsername NVARCHAR(20) NOT NULL,
        ToUsername NVARCHAR(20) NOT NULL,
        EncryptedMessage NVARCHAR(MAX) NOT NULL,
        Signature NVARCHAR(MAX) NULL,
        SentAt DATETIME2 DEFAULT GETDATE(),
        CONSTRAINT FK_Messages_FromUser FOREIGN KEY (FromUsername) REFERENCES Users(Username),
        CONSTRAINT FK_Messages_ToUser FOREIGN KEY (ToUsername) REFERENCES Users(Username)
    );
    CREATE INDEX IX_Messages_FromTo ON Messages(FromUsername, ToUsername);
END
GO

-- FriendRequests table (loi moi ket ban)
IF NOT EXISTS (SELECT *
FROM sys.tables
WHERE name = 'FriendRequests')
BEGIN
    CREATE TABLE FriendRequests
    (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        FromUsername NVARCHAR(20) NOT NULL,
        ToUsername NVARCHAR(20) NOT NULL,
        Status NVARCHAR(10) NOT NULL DEFAULT 'pending',
        -- pending, accepted, rejected
        CreatedAt DATETIME2 DEFAULT GETDATE(),
        CONSTRAINT FK_FR_From FOREIGN KEY (FromUsername) REFERENCES Users(Username),
        CONSTRAINT FK_FR_To FOREIGN KEY (ToUsername) REFERENCES Users(Username),
        CONSTRAINT UQ_FriendRequest UNIQUE (FromUsername, ToUsername)
    );
END
GO

-- Friends table (danh sach ban be)
IF NOT EXISTS (SELECT *
FROM sys.tables
WHERE name = 'Friends')
BEGIN
    CREATE TABLE Friends
    (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Username1 NVARCHAR(20) NOT NULL,
        Username2 NVARCHAR(20) NOT NULL,
        CreatedAt DATETIME2 DEFAULT GETDATE(),
        CONSTRAINT FK_Friends_U1 FOREIGN KEY (Username1) REFERENCES Users(Username),
        CONSTRAINT FK_Friends_U2 FOREIGN KEY (Username2) REFERENCES Users(Username),
        CONSTRAINT UQ_Friends UNIQUE (Username1, Username2)
    );
END
GO

PRINT 'SecChatDB database created successfully!';
GO
