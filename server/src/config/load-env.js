'use strict';
// Carga server/.env en process.env. Solo se invoca desde los puntos de entrada
// (server.js y scripts), nunca desde los módulos, para que las pruebas controlen el entorno.
const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env'), quiet: true });
