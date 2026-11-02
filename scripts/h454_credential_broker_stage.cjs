// Run inside the broker container; the bearer arrives only on stdin.
const net = require('node:net');
const chunks = [];
let size = 0;
process.stdin.on('error', () => process.exit(2));
process.stdin.on('data', chunk => {
  size += chunk.length;
  if (size > 264) process.exit(2);
  chunks.push(chunk);
});
process.stdin.on('end', () => {
  const input = Buffer.concat(chunks), socket = net.connect(38181, '127.0.0.1');
  let response = '';
  socket.on('connect', () => socket.end(input));
  socket.on('data', chunk => {
    response += chunk;
    if (response.length > 64) socket.destroy();
  });
  socket.on('error', () => process.exit(2));
  socket.on('close', () => {
    input.fill(0); for (const chunk of chunks) chunk.fill(0);
    if (response !== 'H454_BROKER_TOKEN_STAGED') process.exit(2);
    process.stdout.write('H454_BROKER_TOKEN_STAGED', () => process.exit(0));
  });
  socket.setTimeout(5000, () => socket.destroy());
});
