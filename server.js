const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Serve files from the 'public' directory
app.use(express.static('public'));

io.on('connection', (socket) => {
    // 1. Notify others that a new peer has joined
    socket.broadcast.emit('new-peer', { id: socket.id });

    // 2. Handshake Forwarding (Public Key Exchange)
    socket.on('signal-handshake', (data) => {
        socket.broadcast.emit('signal-handshake', {
            sender: socket.id,
            publicKey: data.publicKey
        });
    });

    // 3. Encrypted Message Routing
    socket.on('secure-msg', (data) => {
        // Broadcast to everyone else 
        socket.broadcast.emit('secure-msg', data);
    });

    // 4. Typing Indicator Routing
    socket.on('typing', (isTyping) => {
        socket.broadcast.emit('typing', isTyping);
    });

    socket.on('disconnect', () => {
        // Optional: Notify peers that user left
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));