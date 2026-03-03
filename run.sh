#!/bin/bash

# AFDF - Run Both Frontend and Backend

echo "Starting AFDF Backend (port 3001)..."
cd server
npm install 2>/dev/null
node server.js &
BACKEND_PID=$!

cd ..

echo "Starting AFDF Frontend (port 8080)..."
npm run dev &

echo ""
echo "=============================================="
echo "AFDF is running!"
echo "Frontend: http://localhost:8080"
echo "Backend:  http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop both servers"
echo "=============================================="

# Wait for Ctrl+C
trap "kill $BACKEND_PID 2>/dev/null; exit" INT TERM
wait
