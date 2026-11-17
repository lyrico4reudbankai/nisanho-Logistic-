-- Safe additive migration for Nisanho Logistics (SQL Server)
-- Run manually against your existing database. Does not delete data.
-- This project is currently configured for NisanhoAdmin; update the USE
-- target if SQL_DATABASE in your .env points to a different database.

USE [NisanhoAdmin];
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME='admin_users')
BEGIN
    CREATE TABLE dbo.admin_users (
        id INT IDENTITY(1,1) PRIMARY KEY,
        email NVARCHAR(200) NOT NULL UNIQUE,
        password_hash NVARCHAR(255) NOT NULL,
        full_name NVARCHAR(200) NULL,
        is_active BIT NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME NOT NULL DEFAULT GETDATE()
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME='admin_audit_log')
BEGIN
    CREATE TABLE dbo.admin_audit_log (
        id INT IDENTITY(1,1) PRIMARY KEY,
        admin_email NVARCHAR(200) NOT NULL,
        action NVARCHAR(50) NOT NULL,
        order_id INT NULL,
        details NVARCHAR(MAX) NULL,
        created_at DATETIME NOT NULL DEFAULT GETDATE()
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME='contact_messages')
BEGIN
    CREATE TABLE dbo.contact_messages (
        id INT IDENTITY(1,1) PRIMARY KEY,
        full_name NVARCHAR(200) NOT NULL,
        email NVARCHAR(200) NOT NULL,
        subject NVARCHAR(200) NULL,
        message NVARCHAR(MAX) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT GETDATE()
    );
END
GO

-- Ensure orders.status supports workflow values already used by app (no data change)
-- Ensure helpful indexes exist (safe if already present)
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_orders_status' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE INDEX IX_orders_status ON dbo.orders(status);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_orders_submission_date' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE INDEX IX_orders_submission_date ON dbo.orders(submission_date DESC);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_orders_customer_id' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE INDEX IX_orders_customer_id ON dbo.orders(customer_id);
GO
