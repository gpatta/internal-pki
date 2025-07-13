// server.js
const tls = require('tls');
const fs = require('fs');
const path = require('path');


// --- Configuration ---
const CONFIG = {
    PORT: process.env.PORT || 5060,
    // HOST: process.env.HOST || '127.0.0.1',
    HOST: process.env.HOST || '0.0.0.0',
    UPLOADS_DIR: 'received',
    ALLOWED_FORMATS: ['.txt', '.bin', '.gz'],
    TLS_OPTIONS: {
        key: fs.readFileSync(process.env.SERVER_KEY_PATH || 'certs/localhost.key.pem'),
        cert: fs.readFileSync(process.env.SERVER_CERT_PATH || 'certs/localhost.chain.cert.pem'),
        requestCert: true, 
        rejectUnauthorized: true, 
        ca: [ fs.readFileSync(process.env.CA_CERT_PATH || 'certs/ca.cert.pem') ]
    }
};


// --- The TLS Server ---
const server = tls.createServer(CONFIG.TLS_OPTIONS, (socket) => {
    console.log(`[INFO] Client connected: ${socket.remoteAddress}:${socket.remotePort}`);
    console.log(`       Authorized: ${socket.authorized}`);
    if (!socket.authorized) {
        console.log(`[WARN] Connection not authorized: ${socket.authorizationError}`);
    }

    // --- State variables for this specific connection ---
    let state = 'AWAITING_HEADER';
    let internalBuffer = Buffer.alloc(0);
    let metadataLength = 0;
    let fileInfo = {};
    let fileWriter = null;
    let receivedFileBytes = 0;

    const resetForNextFile = () => {
        state = 'AWAITING_HEADER';
        fileInfo = {};
        fileWriter = null;
        receivedFileBytes = 0;
        console.log('[INFO] State reset. Awaiting next file header.');
    };

    socket.on('data', (chunk) => {
        internalBuffer = Buffer.concat([internalBuffer, chunk]);

        // Process buffer as long as there's enough data for the current state
        while (true) {
            switch (state) {
                case 'AWAITING_HEADER':
                    if (internalBuffer.length >= 4) {
                        metadataLength = internalBuffer.readUInt32BE(0);
                        internalBuffer = internalBuffer.slice(4);
                        state = 'AWAITING_METADATA';
                        console.log(`[STATE] Got header. Expecting ${metadataLength} bytes of metadata.`);
                        // Continue to next case in the same loop iteration
                    } else {
                        return; // Not enough data, wait for more
                    }
                    break;

                case 'AWAITING_METADATA':
                    if (internalBuffer.length >= metadataLength) {
                        const metadata = internalBuffer.slice(0, metadataLength);
                        internalBuffer = internalBuffer.slice(metadataLength);

                        const filenameLength = metadata.readUInt8(0);
                        const filename = metadata.slice(1, 1 + filenameLength).toString('utf8');
                        const fileSize = metadata.readBigUInt64BE(1 + filenameLength); // Use BigInt for 64-bit

                        fileInfo = { filename: path.basename(filename), size: Number(fileSize) };
                        console.log('[STATE] Received metadata:', fileInfo);

                        // --- Validation ---
                        const fileExt = path.extname(fileInfo.filename).toLowerCase();
                        if (!CONFIG.ALLOWED_FORMATS.includes(fileExt)) {
                            console.error(`[ERROR] Invalid file format: ${fileExt}. Closing connection.`);
                            socket.end();
                            return;
                        }

                        // --- Prepare for file stream ---
                        const destinationPath = path.join(CONFIG.UPLOADS_DIR, fileInfo.filename);
                        fileWriter = fs.createWriteStream(destinationPath);
                        state = 'RECEIVING_FILE';
                        console.log('[STATE] Metadata OK. Sending ACK and waiting for file data.');
                        socket.write('a'); // Send ACK
                    } else {
                        return; // Not enough data, wait for more
                    }
                    break;

                case 'RECEIVING_FILE':
                    const bytesNeeded = fileInfo.size - receivedFileBytes;
                    const bytesToWrite = Math.min(bytesNeeded, internalBuffer.length);

                    if (bytesToWrite > 0) {
                        fileWriter.write(internalBuffer.slice(0, bytesToWrite));
                        internalBuffer = internalBuffer.slice(bytesToWrite);
                        receivedFileBytes += bytesToWrite;
                        process.stdout.write(`       Receiving... ${((receivedFileBytes / fileInfo.size) * 100).toFixed(2)}%\r`);
                    }

                    if (receivedFileBytes === fileInfo.size) {
                        console.log('\n[SUCCESS] File received completely.');
                        fileWriter.end();
                        socket.write('a'); // Send final ACK for this file
                        resetForNextFile();
                    }
                    
                    if (internalBuffer.length === 0) {
                        return; // All buffered data processed, wait for more.
                    }
                    break;
                
                default:
                    console.error(`[ERROR] Unknown state: ${state}`);
                    socket.end();
                    return;
            }
        }
    });

    socket.on('end', () => {
        console.log('\n[INFO] Client disconnected.');
    });
    
    socket.on('error', (err) => {
        console.error(`[ERROR] Socket error from ${socket.remoteAddress}:`, err.message);
    });

    socket.on('close', () => {
        console.log(`[INFO] Connection closed for ${socket.remoteAddress}.`);
    });
});

// --- Start the server ---
server.listen(CONFIG.PORT, CONFIG.HOST, () => {
    
    // Create the uploads directory
    if (!fs.existsSync(CONFIG.UPLOADS_DIR)) {
        console.log(`Creating uploads directory: ${CONFIG.UPLOADS_DIR}`);
        fs.mkdirSync(CONFIG.UPLOADS_DIR);
    }

    console.log('====================================================');
    console.log(`Secure File Ingestion Server listening on ${CONFIG.HOST}:${CONFIG.PORT}`);
    console.log('Awaiting TLS connections...');
    console.log('====================================================');
});