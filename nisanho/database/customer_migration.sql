-- Safe additive migration: add customer password_hash and is_active columns if missing.
-- Does not delete or modify existing data.

IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME='customers' AND COLUMN_NAME='password_hash'
)
BEGIN
    ALTER TABLE dbo.customers ADD password_hash NVARCHAR(255) NULL;
END
GO

IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME='customers' AND COLUMN_NAME='is_active'
)
BEGIN
    ALTER TABLE dbo.customers ADD is_active BIT NOT NULL DEFAULT 1;
END
GO

IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME='customers' AND COLUMN_NAME='updated_at'
)
BEGIN
    ALTER TABLE dbo.customers ADD updated_at DATETIME NULL;
END
GO
