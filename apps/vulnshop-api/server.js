const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet.frameguard({ action: 'deny' }));
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', service: 'vulnshop-api-node' });
});

app.listen(PORT, () => {
  console.log(`Vulnshop API listening on port ${PORT}`);
});

