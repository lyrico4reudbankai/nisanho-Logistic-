-- Safe additive migration for real-time orders/chat (SQL Server)
-- Run against existing NisanhoAdmin. Does not delete or modify existing data.

IF OBJECT_ID('dbo.conversations', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.conversations (
        id INT IDENTITY(1,1) PRIMARY KEY,
        customer_id INT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME NOT NULL DEFAULT GETDATE(),
        last_message_at DATETIME NULL,
        CONSTRAINT FK_conversations_customer FOREIGN KEY (customer_id) REFERENCES dbo.customers(id),
        CONSTRAINT UQ_conversations_customer UNIQUE (customer_id)
    );
END
GO

IF OBJECT_ID('dbo.chat_messages', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.chat_messages (
        id INT IDENTITY(1,1) PRIMARY KEY,
        conversation_id INT NOT NULL,
        sender_role NVARCHAR(20) NOT NULL, -- 'admin' or 'customer'
        sender_id INT NULL,
        sender_name NVARCHAR(200) NULL,
        body NVARCHAR(MAX) NOT NULL,
        is_read BIT NOT NULL DEFAULT 0,
        read_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT GETDATE(),
        CONSTRAINT FK_chat_messages_conversation FOREIGN KEY (conversation_id) REFERENCES dbo.conversations(id)
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_chat_messages_conversation_created' AND object_id = OBJECT_ID('dbo.chat_messages'))
    CREATE INDEX IX_chat_messages_conversation_created ON dbo.chat_messages(conversation_id, created_at);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_chat_messages_unread' AND object_id = OBJECT_ID('dbo.chat_messages'))
    CREATE INDEX IX_chat_messages_unread ON dbo.chat_messages(conversation_id, is_read, sender_role);
GO
