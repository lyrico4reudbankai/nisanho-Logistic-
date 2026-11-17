-- =====================================================================
-- Nissanho Logistics - Admin Dashboard Database Schema (SQL Server)
-- =====================================================================
-- Run this script on your local SQL Server instance (e.g. via SSMS, 
-- sqlcmd, or any SQL client connected to your server).
--
-- FRESH INSTALL ONLY: this script creates/selects NisanhoAdmin and
-- creates stored procedures. For an existing configured database, do not
-- run this file; apply database/migrations.sql instead.
-- =====================================================================

-- Create NisanhoAdmin only for a new installation.
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'NisanhoAdmin')
BEGIN
    CREATE DATABASE [NisanhoAdmin];
END
GO

USE [NisanhoAdmin];
GO

-- ---------------------------------------------------------------------
-- Customers table (reused by both the customer page and the admin dashboard)
-- ---------------------------------------------------------------------
IF OBJECT_ID('dbo.customers', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.customers (
        id INT IDENTITY(1,1) PRIMARY KEY,
        full_name NVARCHAR(200) NOT NULL,
        company_name NVARCHAR(200) NULL,
        email NVARCHAR(200) NOT NULL,
        phone NVARCHAR(50) NULL,
        created_at DATETIME NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME NOT NULL DEFAULT GETDATE(),
        CONSTRAINT UQ_customers_email UNIQUE (email)
    );
END
GO

-- ---------------------------------------------------------------------
-- Orders table (orders submitted through the customer page live here)
-- ---------------------------------------------------------------------
IF OBJECT_ID('dbo.orders', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.orders (
        id INT IDENTITY(1,1) PRIMARY KEY,
        tracking_number NVARCHAR(50) NULL,
        customer_id INT NULL,
        full_name NVARCHAR(200) NOT NULL,
        company_name NVARCHAR(200) NULL,
        email NVARCHAR(200) NOT NULL,
        phone NVARCHAR(50) NULL,
        service_required NVARCHAR(100) NULL,
        shipping_method NVARCHAR(50) NULL,
        origin NVARCHAR(200) NULL,
        destination NVARCHAR(200) NULL,
        cargo_type NVARCHAR(200) NULL,
        weight NVARCHAR(100) NULL,
        message NVARCHAR(MAX) NULL,
        status NVARCHAR(20) NOT NULL DEFAULT 'pending',
        submission_date DATETIME NOT NULL DEFAULT GETDATE(),
        approved_at DATETIME NULL,
        approved_by NVARCHAR(200) NULL,
        rejected_at DATETIME NULL,
        rejected_by NVARCHAR(200) NULL,
        rejection_reason NVARCHAR(MAX) NULL,
        created_at DATETIME NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME NOT NULL DEFAULT GETDATE(),
        CONSTRAINT FK_orders_customer FOREIGN KEY (customer_id) REFERENCES dbo.customers(id)
    );
END
GO

-- ---------------------------------------------------------------------
-- Admin audit log (records who approved/rejected each order and when)
-- ---------------------------------------------------------------------
IF OBJECT_ID('dbo.admin_audit_log', 'U') IS NULL
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

IF OBJECT_ID('dbo.contact_messages', 'U') IS NULL
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

-- ---------------------------------------------------------------------
-- Indexes (safe to re-add; missing indexes are created only if absent)
-- ---------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = N'IX_orders_status' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE INDEX IX_orders_status ON dbo.orders(status);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = N'IX_orders_email' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE INDEX IX_orders_email ON dbo.orders(email);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = N'IX_orders_submission_date' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE INDEX IX_orders_submission_date ON dbo.orders(submission_date);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = N'IX_customers_email' AND object_id = OBJECT_ID('dbo.customers'))
    CREATE INDEX IX_customers_email ON dbo.customers(email);
GO

-- ---------------------------------------------------------------------
-- Stored procedure: approve an order (parameterized, prevents duplicates)
-- ---------------------------------------------------------------------
IF OBJECT_ID('dbo.sp_approve_order', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_approve_order;
GO

CREATE PROCEDURE dbo.sp_approve_order
    @order_id INT,
    @admin_email NVARCHAR(200)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @customer_email NVARCHAR(200);
    DECLARE @customer_name NVARCHAR(200);
    DECLARE @customer_company NVARCHAR(200);
    DECLARE @customer_phone NVARCHAR(50);
    DECLARE @existing_customer_id INT;
    DECLARE @order_status NVARCHAR(20);

    -- Read order contact info
    SELECT 
        @customer_email = email,
        @customer_name = full_name,
        @customer_company = company_name,
        @customer_phone = phone,
        @order_status = status
    FROM dbo.orders
    WHERE id = @order_id;

    -- Only pending orders can be approved
    IF @order_status <> 'pending'
    BEGIN
        THROW 50001, 'Only pending orders can be approved.', 1;
        RETURN;
    END

    -- Prevent duplicate customers: reuse existing customer by email
    SELECT @existing_customer_id = id
    FROM dbo.customers
    WHERE LOWER(email) = LOWER(@customer_email);

    IF @existing_customer_id IS NULL
    BEGIN
        INSERT INTO dbo.customers (full_name, company_name, email, phone, updated_at)
        VALUES (@customer_name, @customer_company, @customer_email, @customer_phone, GETDATE());

        SELECT @existing_customer_id = SCOPE_IDENTITY();
    END
    ELSE
    BEGIN
        UPDATE dbo.customers
        SET full_name = @customer_name,
            company_name = COALESCE(@customer_company, company_name),
            phone = COALESCE(@customer_phone, phone),
            updated_at = GETDATE()
        WHERE id = @existing_customer_id;
    END

    -- Approve the order and link it to the customer record
    UPDATE dbo.orders
    SET customer_id = @existing_customer_id,
        status = 'approved',
        approved_at = GETDATE(),
        approved_by = @admin_email,
        updated_at = GETDATE()
    WHERE id = @order_id;

    -- Audit trail
    INSERT INTO dbo.admin_audit_log (admin_email, action, order_id, details)
    VALUES (@admin_email, 'approve', @order_id, 'Order approved and linked to customer id ' + CAST(@existing_customer_id AS NVARCHAR(20)));
END
GO

-- ---------------------------------------------------------------------
-- Stored procedure: reject an order with a reason
-- ---------------------------------------------------------------------
IF OBJECT_ID('dbo.sp_reject_order', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_reject_order;
GO

CREATE PROCEDURE dbo.sp_reject_order
    @order_id INT,
    @admin_email NVARCHAR(200),
    @rejection_reason NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @order_status NVARCHAR(20);

    SELECT @order_status = status FROM dbo.orders WHERE id = @order_id;

    IF @order_status <> 'pending'
    BEGIN
        THROW 50002, 'Only pending orders can be rejected.', 1;
        RETURN;
    END

    UPDATE dbo.orders
    SET status = 'rejected',
        rejection_reason = @rejection_reason,
        rejected_at = GETDATE(),
        rejected_by = @admin_email,
        updated_at = GETDATE()
    WHERE id = @order_id;

    INSERT INTO dbo.admin_audit_log (admin_email, action, order_id, details)
    VALUES (@admin_email, 'reject', @order_id, @rejection_reason);
END
GO

PRINT 'NisanhoAdmin schema installed successfully.';
GO
