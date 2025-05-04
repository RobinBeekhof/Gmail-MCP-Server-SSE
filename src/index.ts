#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js"
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { google } from 'googleapis';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import { createEmailMessage } from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration
let oauth2Client: OAuth2Client;

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

async function loadCredentials() {
    try {
        // Create config directory if it doesn't exist
        if (!process.env.GMAIL_OAUTH_PATH && !CREDENTIALS_PATH && !fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        // Check for OAuth keys in current directory first, then in config directory
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
        let oauthPath = OAUTH_PATH;

        if (fs.existsSync(localOAuthPath)) {
            // If found in current directory, copy to config directory
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            console.log('OAuth keys found in current directory, copied to global config.');
        }

        if (!fs.existsSync(OAUTH_PATH)) {
            console.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
            process.exit(1);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;

        if (!keys) {
            console.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
            process.exit(1);
        }

        const callback = process.argv[2] === 'auth' && process.argv[3]
            ? process.argv[3]
            : "http://localhost:3000/oauth2callback";

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );

        if (fs.existsSync(CREDENTIALS_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
            oauth2Client.setCredentials(credentials);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

async function authenticate() {
    const server = http.createServer();
    server.listen(3000);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: ['https://www.googleapis.com/auth/gmail.modify'],
        });

        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens));

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                reject(error);
            }
        });
    });
}

// --- MCP Tool registrations ---
function registerGmailTools(server: McpServer, gmail: any) {

    server.tool("send_email", SendEmailSchema.shape, async (args) => {
        const message = createEmailMessage(args);
        const encodedMessage = Buffer.from(message).toString('base64')
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const req: { raw: string, threadId?: string } = { raw: encodedMessage };
        if (args.threadId) req.threadId = args.threadId;
        const res = await gmail.users.messages.send({
            userId: 'me', requestBody: req,
        });
        return { content: [{ type: "text", text: `Email sent successfully with ID: ${res.data.id}` }] };
    });

    server.tool("draft_email", SendEmailSchema.shape, async (args) => {
        const message = createEmailMessage(args);
        const encodedMessage = Buffer.from(message).toString('base64')
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const req: { raw: string, threadId?: string } = { raw: encodedMessage };
        if (args.threadId) req.threadId = args.threadId;
        const res = await gmail.users.drafts.create({
            userId: 'me', requestBody: { message: req },
        });
        return { content: [{ type: "text", text: `Email draft created successfully with ID: ${res.data.id}` }] };
    });

    server.tool("read_email", ReadEmailSchema.shape, async (args) => {
        const res = await gmail.users.messages.get({
            userId: 'me', id: args.messageId, format: 'full',
        });

        const headers = res.data.payload?.headers || [];
        const subject = headers.find((h: { name: string; }) => h.name?.toLowerCase() === 'subject')?.value || '';
        const from = headers.find((h: { name: string; }) => h.name?.toLowerCase() === 'from')?.value || '';
        const to = headers.find((h: { name: string; }) => h.name?.toLowerCase() === 'to')?.value || '';
        const date = headers.find((h: { name: string; }) => h.name?.toLowerCase() === 'date')?.value || '';
        const threadId = res.data.threadId || '';
        const { text, html } = extractEmailContent(res.data.payload as GmailMessagePart || {});
        const body = text || html || '';
        const contentTypeNote = !text && html ? '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';
        const attachments: EmailAttachment[] = [];
        const processAttachmentParts = (part: GmailMessagePart, path: string = '') => {
            if (part.body && part.body.attachmentId) {
                const filename = part.filename || `attachment-${part.body.attachmentId}`;
                attachments.push({
                    id: part.body.attachmentId, filename: filename,
                    mimeType: part.mimeType || 'application/octet-stream',
                    size: part.body.size || 0
                });
            }
            if (part.parts) {
                part.parts.forEach((subpart: GmailMessagePart) =>
                    processAttachmentParts(subpart, `${path}/parts`));
            }
        };
        if (res.data.payload) processAttachmentParts(res.data.payload as GmailMessagePart);
        const attachmentInfo = attachments.length > 0
            ? `\n\nAttachments (${attachments.length}):\n` +
            attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size / 1024)} KB)`).join('\n') : '';
        return {
            content: [{
                type: "text", text:
                    `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`
            }]
        };
    });

    server.tool("search_emails", SearchEmailsSchema.shape, async (args) => {
        const res = await gmail.users.messages.list({
            userId: 'me',
            q: args.query,
            maxResults: args.maxResults || 10,
        });
        const messages = res.data.messages || [];
        const results = await Promise.all(
            messages.map(async (msg: { id: any; }) => {
                const detail = await gmail.users.messages.get({
                    userId: 'me',
                    id: msg.id!,
                    format: 'metadata',
                    metadataHeaders: ['Subject', 'From', 'Date'],
                });
                const headers = detail.data.payload?.headers || [];
                return {
                    id: msg.id,
                    subject: headers.find((h: { name: string; }) => h.name === 'Subject')?.value || '',
                    from: headers.find((h: { name: string; }) => h.name === 'From')?.value || '',
                    date: headers.find((h: { name: string; }) => h.name === 'Date')?.value || '',
                };
            })
        );
        return {
            content: [{
                type: "text",
                text: results.map(r => `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`).join('\n'),
            }]
        };
    });

    server.tool("modify_email", ModifyEmailSchema.shape, async (args) => {
        const requestBody: any = {};
        if (args.labelIds) requestBody.addLabelIds = args.labelIds;
        if (args.addLabelIds) requestBody.addLabelIds = args.addLabelIds;
        if (args.removeLabelIds) requestBody.removeLabelIds = args.removeLabelIds;
        await gmail.users.messages.modify({
            userId: 'me',
            id: args.messageId,
            requestBody: requestBody,
        });
        return {
            content: [{ type: "text", text: `Email ${args.messageId} labels updated successfully` }]
        };
    });

    server.tool("delete_email", DeleteEmailSchema.shape, async (args) => {
        await gmail.users.messages.delete({
            userId: 'me',
            id: args.messageId,
        });
        return {
            content: [{ type: "text", text: `Email ${args.messageId} deleted successfully` }]
        };
    });

    server.tool("list_email_labels", ListEmailLabelsSchema.shape, async () => {
        const labelResults = await listLabels(gmail);
        const systemLabels = labelResults.system;
        const userLabels = labelResults.user;
        return {
            content: [{
                type: "text",
                text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                    "System Labels:\n" +
                    systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                    "\nUser Labels:\n" +
                    userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
            }]
        };
    });

    // --- Batch tools helper ---
    async function processBatches<T, U>(
        items: T[], batchSize: number, processFn: (batch: T[]) => Promise<U[]>
    ): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
        const successes: U[] = [], failures: { item: T, error: Error }[] = [];
        for (let i = 0; i < items.length; i += batchSize) {
            const batch = items.slice(i, i + batchSize);
            try { successes.push(...await processFn(batch)); }
            catch (error) {
                for (const item of batch) {
                    try { successes.push(...await processFn([item])); }
                    catch (itemError) { failures.push({ item, error: itemError as Error }); }
                }
            }
        }
        return { successes, failures };
    }

    server.tool("batch_modify_emails", BatchModifyEmailsSchema.shape, async (args) => {
        const requestBody: any = {};
        if (args.addLabelIds) requestBody.addLabelIds = args.addLabelIds;
        if (args.removeLabelIds) requestBody.removeLabelIds = args.removeLabelIds;
        const { successes, failures } = await processBatches(
            args.messageIds, args.batchSize || 50,
            async (batch) => Promise.all(batch.map(async (messageId) => {
                await gmail.users.messages.modify({
                    userId: 'me', id: messageId, requestBody: requestBody,
                });
                return { messageId, success: true };
            }))
        );
        let resultText = `Batch label modification complete.\nSuccessfully processed: ${successes.length} messages\n`;
        if (failures.length > 0) {
            resultText += `Failed to process: ${failures.length} messages\n\nFailed message IDs:\n` +
                failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
        }
        return { content: [{ type: "text", text: resultText }] };
    });

    server.tool("batch_delete_emails", BatchDeleteEmailsSchema.shape, async (args) => {
        const { successes, failures } = await processBatches(
            args.messageIds, args.batchSize || 50,
            async (batch) => Promise.all(batch.map(async (messageId) => {
                await gmail.users.messages.delete({ userId: 'me', id: messageId });
                return { messageId, success: true };
            }))
        );
        let resultText = `Batch delete operation complete.\nSuccessfully deleted: ${successes.length} messages\n`;
        if (failures.length > 0) {
            resultText += `Failed to delete: ${failures.length} messages\n\nFailed message IDs:\n` +
                failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
        }
        return { content: [{ type: "text", text: resultText }] };
    });

    server.tool("create_label", CreateLabelSchema.shape, async (args) => {
        const result = await createLabel(gmail, args.name, {
            messageListVisibility: args.messageListVisibility,
            labelListVisibility: args.labelListVisibility,
        });
        return {
            content: [{ type: "text", text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }]
        };
    });

    server.tool("update_label", UpdateLabelSchema.shape, async (args) => {
        const updates: any = {};
        if (args.name) updates.name = args.name;
        if (args.messageListVisibility) updates.messageListVisibility = args.messageListVisibility;
        if (args.labelListVisibility) updates.labelListVisibility = args.labelListVisibility;
        const result = await updateLabel(gmail, args.id, updates);
        return {
            content: [{ type: "text", text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }]
        };
    });

    server.tool("delete_label", DeleteLabelSchema.shape, async (args) => {
        const result = await deleteLabel(gmail, args.id);
        return { content: [{ type: "text", text: result.message }] };
    });

    server.tool("get_or_create_label", GetOrCreateLabelSchema.shape, async (args) => {
        const result = await getOrCreateLabel(gmail, args.name, {
            messageListVisibility: args.messageListVisibility,
            labelListVisibility: args.labelListVisibility,
        });
        const action = result.type === 'user' && result.name === args.name ? 'found existing' : 'created new';
        return {
            content: [{ type: "text", text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }]
        };
    });
}

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    threadId: z.string().optional().describe("Thread ID to reply to"),
    inReplyTo: z.string().optional().describe("Message ID being replied to"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

// Updated schema to include removeLabelIds
const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

// Label management schemas
const CreateLabelSchema = z.object({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Creates a new Gmail label");

const UpdateLabelSchema = z.object({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Updates an existing Gmail label");

const DeleteLabelSchema = z.object({
    id: z.string().describe("ID of the label to delete"),
}).describe("Deletes a Gmail label");

const GetOrCreateLabelSchema = z.object({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Gets an existing label by name or creates it if it doesn't exist");

// Schemas for batch operations
const BatchModifyEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to modify"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

const BatchDeleteEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to delete"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

// Main function
async function main() {
    await loadCredentials();

    if (process.argv[2] === 'auth') {
        await authenticate();
        console.log('Authentication completed successfully');
        process.exit(0);
    }
    // Initialize Gmail API
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Server implementation
    const server = new McpServer({
        name: "gmail",
        version: "1.0.0",
        capabilities: { tools: {} },
    });

    const app = express();
    app.use(express.json());

    const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
    const sseTransports: { [sessionId: string]: SSEServerTransport } = {};

    // ========== Streamable Transport endpoint ==========
    // Handle POST requests for client-to-server communication
    app.post('/mcp', async (req, res) => {
        // Check for existing session ID
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (sessionId && transports[sessionId]) {
            // Reuse existing transport
            transport = transports[sessionId];
        } else if (!sessionId && isInitializeRequest(req.body)) {
            // New initialization request
            transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (sessionId) => {
                    // Store the transport by session ID
                    transports[sessionId] = transport;
                }
            });

            // Clean up transport when closed
            transport.onclose = () => {
                if (transport.sessionId) {
                    delete transports[transport.sessionId];
                }
            };
            const server = new McpServer({
                name: "example-server",
                version: "1.0.0"
            });

            registerGmailTools(server, gmail);

            // Connect to the MCP server
            await server.connect(transport);
        } else {
            // Invalid request
            res.status(400).json({
                jsonrpc: '2.0',
                error: {
                    code: -32000,
                    message: 'Bad Request: No valid session ID provided',
                },
                id: null,
            });
            return;
        }

        // Handle the request
        await transport.handleRequest(req, res, req.body);
    });

    // For notifications and clean shutdown
    const handleSessionRequest = async (req: express.Request, res: express.Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !transports[sessionId]) {
            res.status(400).send('Invalid or missing session ID');
            return;
        }
        const transport = transports[sessionId];
        await transport.handleRequest(req, res);
    };

    app.get('/mcp', handleSessionRequest);
    app.delete('/mcp', handleSessionRequest);


    // ========== SSE Transport endpoint ==========
    app.get('/sse', async (req, res) => {
        // Generate or get session id (always use header if client reconnects)
        const sessionId = (req.headers['mcp-session-id'] as string) || randomUUID();
        console.log("GET /sse received", sessionId);
        // We use the same endpoint for GET and POST:
        const endpointPath = '/messages';
        const nodeRes: http.ServerResponse = res as any; // Express Response is compatible

        // Prevent duplicate sessions
        if (sseTransports[sessionId]) {
            res.status(400).send('Session already exists');
            return;
        }

        // Instantiate transport
        const transport = new SSEServerTransport(endpointPath, nodeRes);
        sseTransports[sessionId] = transport;

        transport.onclose = () => {
            delete sseTransports[sessionId];
        };

        // Register MCP tools for this session
        const server = new McpServer({
            name: "gmail",
            version: "1.0.0",
            capabilities: { tools: {} },
        });
        registerGmailTools(server, gmail);

        // Connect transport to server (starts SSE)
        await server.connect(transport);

        // End session if client closes connection
        req.on('close', () => transport.close());
    });

    // SSE POST: Handles messages from client for existing sessions
    app.post('/messages', async (req, res) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        console.log("POST /messages", { sessionId, body: req.body });
        if (!sessionId || !sseTransports[sessionId]) {
            res.status(400).json({
                jsonrpc: '2.0',
                error: {
                    code: -32000,
                    message: 'Bad Request: No valid session ID provided',
                },
                id: null,
            });
            return;
        }
        const transport = sseTransports[sessionId];
        try {
            console.log("Handling POST for session", sessionId, req.body);
            await transport.handlePostMessage(req as any, res as any, req.body);
            console.log("POST handled");
        } catch (err) {
            console.error("Error handling POST:", err);
            if (!res.headersSent)
                res.status(500).json({ error: (err as Error).message });
        }
    });

    // Optional (but usually unused): SSE DELETE handler to trigger session close
    app.delete('/sse', async (req, res) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !sseTransports[sessionId]) {
            res.status(400).send('Invalid or missing session ID');
            return;
        }
        await sseTransports[sessionId].close();
        res.status(204).end();
    });


    app.listen(3000, () => {
        console.log('Gmail MCP HTTP/SSE server running at http://localhost:3000');
    });
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});
