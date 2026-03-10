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

PRINT 'SecChatDB database created successfully!';
GO
